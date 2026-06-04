#!/usr/bin/env python3
"""Simulate a LoRa gateway speaking the Semtech UDP packet-forwarder
protocol, to verify the firewall is correctly forwarding UDP traffic
to ChirpStack (and that ChirpStack's replies make it back).

Three stages, run in order, each gated on the previous:

  1. PULL_DATA -> PULL_ACK
     Proves bidirectional UDP through the firewall.

  2. PUSH_DATA stat -> PUSH_ACK
     The gateway "checks in" with stats. After this, the gateway with
     this EUI should appear (or update "last seen") in the ChirpStack UI.

  3. PUSH_DATA join-request -> PUSH_ACK [+ PULL_RESP join-accept]
     Sends a synthetic LoRaWAN 1.0 Join-Request rxpk. PUSH_ACK proves
     the uplink path; PULL_RESP only comes back if the device is
     provisioned AND the MIC is valid. With the default placeholder MIC
     ChirpStack will accept the frame but reject the join, which is
     fine for firewall testing.

Example:
    python3 chirpstack_gw_sim.py \\
        --host firewall.example.com --udp 1701 \\
        --gateway-eui 0102030405060708 \\
        --dev-eui 1122334455667788

For an ongoing "gateway is online" test:
    python3 chirpstack_gw_sim.py --host ... --udp 1701 --keep-alive
"""
import argparse
import base64
import json
import random
import socket
import struct
import sys
import time

PROTO_VERSION = 2

PUSH_DATA = 0x00
PUSH_ACK  = 0x01
PULL_DATA = 0x02
PULL_RESP = 0x03
PULL_ACK  = 0x04
TX_ACK    = 0x05

NAME = {
    PUSH_DATA: "PUSH_DATA", PUSH_ACK: "PUSH_ACK",
    PULL_DATA: "PULL_DATA", PULL_RESP: "PULL_RESP",
    PULL_ACK: "PULL_ACK", TX_ACK: "TX_ACK",
}


def make_header(token: int, packet_id: int, gw_eui: bytes) -> bytes:
    """Semtech header: version | token (BE u16) | packet id | gateway EUI (8B)."""
    assert len(gw_eui) == 8
    return struct.pack(">B H B 8s", PROTO_VERSION, token, packet_id, gw_eui)


def parse(data: bytes):
    if len(data) < 4:
        return None
    version, token, pid = struct.unpack(">B H B", data[:4])
    return version, token, pid, data[4:]


def send_recv(s: socket.socket, addr, pkt: bytes, expected_pid: int,
              timeout: float = 5.0):
    s.sendto(pkt, addr)
    sent_token = struct.unpack(">H", pkt[1:3])[0]
    deadline = time.time() + timeout
    while time.time() < deadline:
        s.settimeout(max(0.01, deadline - time.time()))
        try:
            data, _ = s.recvfrom(4096)
        except socket.timeout:
            return None
        parsed = parse(data)
        if not parsed:
            continue
        _, token, pid, _ = parsed
        if pid == expected_pid and token == sent_token:
            return parsed
        # otherwise drop & keep waiting; could be a stray PULL_RESP for an old PULL_DATA
    return None


def stage_pull_data(s, addr, gw_eui) -> bool:
    token = random.randint(0, 0xFFFF)
    pkt = make_header(token, PULL_DATA, gw_eui)
    print(f"-> PULL_DATA token=0x{token:04x} gw={gw_eui.hex()}")
    resp = send_recv(s, addr, pkt, PULL_ACK)
    if resp is None:
        print("   TIMEOUT — no PULL_ACK. Possible causes:")
        print("     * `proxy_responses 0` still in services.conf "
              "(see `podman compose exec nginx cat /etc/nginx/dynamic/services.conf`)")
        print("     * UDP port not published on the host (check ports: in docker-compose.yml)")
        print("     * this source IP isn't allowlisted on the UDP service")
        print("     * ChirpStack isn't listening on the target port")
        return False
    print("   <- PULL_ACK ok")
    return True


def stage_push_stat(s, addr, gw_eui) -> bool:
    token = random.randint(0, 0xFFFF)
    body = json.dumps({
        "stat": {
            "time": time.strftime("%Y-%m-%d %H:%M:%S GMT", time.gmtime()),
            "lati": 0.0, "long": 0.0, "alti": 0,
            "rxnb": 0, "rxok": 0, "rxfw": 0,
            "ackr": 100.0, "dwnb": 0, "txnb": 0,
        }
    }).encode()
    pkt = make_header(token, PUSH_DATA, gw_eui) + body
    print(f"-> PUSH_DATA stat token=0x{token:04x}")
    resp = send_recv(s, addr, pkt, PUSH_ACK)
    if resp is None:
        print("   TIMEOUT — no PUSH_ACK.")
        return False
    print("   <- PUSH_ACK ok (gateway should now show 'last seen' in ChirpStack)")
    return True


def build_join_request_phy(dev_eui: bytes, join_eui: bytes, dev_nonce: int,
                           mic: bytes = b"\x00\x00\x00\x00") -> bytes:
    """LoRaWAN 1.0 Join-Request PHYPayload (23 bytes).

    Layout: MHDR(0x00) | JoinEUI (little-endian) | DevEUI (little-endian)
            | DevNonce (LE u16) | MIC (4B)
    """
    assert len(dev_eui) == 8 and len(join_eui) == 8 and len(mic) == 4
    return bytes([0x00]) + join_eui[::-1] + dev_eui[::-1] \
        + struct.pack("<H", dev_nonce) + mic


def stage_join_request(s, addr, gw_eui, dev_eui, join_eui,
                       freq_mhz: float, listen_secs: float) -> bool:
    token = random.randint(0, 0xFFFF)
    nonce = random.randint(0, 0xFFFF)
    phy = build_join_request_phy(dev_eui, join_eui, nonce)
    rxpk = {
        "rxpk": [{
            "tmst": int((time.time() * 1e6) % 2**32),
            "time": time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime()),
            "chan": 0, "rfch": 0,
            "freq": freq_mhz,
            "stat": 1, "modu": "LORA",
            "datr": "SF7BW125", "codr": "4/5",
            "rssi": -80, "lsnr": 7.0,
            "size": len(phy),
            "data": base64.b64encode(phy).decode(),
        }]
    }
    pkt = make_header(token, PUSH_DATA, gw_eui) + json.dumps(rxpk).encode()
    print(f"-> PUSH_DATA Join-Request DevEUI={dev_eui.hex()} "
          f"JoinEUI={join_eui.hex()} nonce=0x{nonce:04x} (placeholder MIC)")
    resp = send_recv(s, addr, pkt, PUSH_ACK)
    if resp is None:
        print("   TIMEOUT — no PUSH_ACK to Join-Request.")
        return False
    print("   <- PUSH_ACK ok")

    print(f"   listening {listen_secs:.0f}s for PULL_RESP (Join-Accept)...")
    deadline = time.time() + listen_secs
    while time.time() < deadline:
        s.settimeout(max(0.01, deadline - time.time()))
        try:
            data, _ = s.recvfrom(4096)
        except socket.timeout:
            break
        parsed = parse(data)
        if not parsed:
            continue
        _, rtok, pid, body = parsed
        print(f"   <- {NAME.get(pid, hex(pid))} token=0x{rtok:04x}")
        if pid == PULL_RESP:
            preview = body[:200] + (b"..." if len(body) > 200 else b"")
            print(f"      Join-Accept payload: {preview!r}")
            return True
    print("   no Join-Accept — expected when the device isn't provisioned in "
          "ChirpStack or the MIC is wrong (default is a placeholder).")
    return True  # PUSH_ACK alone is enough to prove forwarding works


def keep_alive_loop(s, addr, gw_eui, interval: float) -> None:
    print(f"keep-alive: PULL_DATA every {interval:.0f}s — Ctrl-C to stop")
    try:
        while True:
            token = random.randint(0, 0xFFFF)
            pkt = make_header(token, PULL_DATA, gw_eui)
            s.sendto(pkt, addr)
            try:
                s.settimeout(2.0)
                data, _ = s.recvfrom(4096)
                parsed = parse(data)
                if parsed and parsed[2] == PULL_ACK:
                    print(f"[{time.strftime('%H:%M:%S')}] PULL_DATA -> PULL_ACK")
                else:
                    print(f"[{time.strftime('%H:%M:%S')}] unexpected reply: {data!r}")
            except socket.timeout:
                print(f"[{time.strftime('%H:%M:%S')}] PULL_DATA -> TIMEOUT")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nstopped.")


def parse_eui(s: str) -> bytes:
    s = s.replace(":", "").replace("-", "").lower()
    if len(s) != 16 or any(c not in "0123456789abcdef" for c in s):
        raise argparse.ArgumentTypeError(f"EUI must be 16 hex chars, got {s!r}")
    return bytes.fromhex(s)


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--host", required=True, help="firewall public hostname/IP")
    p.add_argument("--udp", type=int, default=1701, help="firewall public UDP port")
    p.add_argument("--gateway-eui", type=parse_eui, default=parse_eui("0102030405060708"))
    p.add_argument("--dev-eui", type=parse_eui, default=parse_eui("1122334455667788"))
    p.add_argument("--join-eui", type=parse_eui, default=parse_eui("0000000000000000"))
    p.add_argument("--freq", type=float, default=868.1, help="rxpk freq in MHz")
    p.add_argument("--join-listen", type=float, default=6.0,
                   help="seconds to wait for a Join-Accept PULL_RESP")
    p.add_argument("--skip-stat", action="store_true")
    p.add_argument("--skip-joinreq", action="store_true")
    p.add_argument("--keep-alive", action="store_true",
                   help="after the join attempt, loop PULL_DATA every 10s")
    p.add_argument("--keep-alive-interval", type=float, default=10.0)
    args = p.parse_args()

    addr = (args.host, args.udp)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    if not stage_pull_data(s, addr, args.gateway_eui):
        sys.exit(1)

    if not args.skip_stat:
        stage_push_stat(s, addr, args.gateway_eui)

    if not args.skip_joinreq:
        stage_join_request(s, addr, args.gateway_eui, args.dev_eui,
                           args.join_eui, args.freq, args.join_listen)

    if args.keep_alive:
        keep_alive_loop(s, addr, args.gateway_eui, args.keep_alive_interval)


if __name__ == "__main__":
    main()
