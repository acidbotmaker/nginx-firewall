#!/usr/bin/env python3
"""Simulate a LoRa gateway speaking the Semtech UDP packet-forwarder
protocol, to verify the firewall is correctly forwarding UDP traffic
to ChirpStack (and that ChirpStack's replies make it back).

Stages, run in order, each gated on the previous:

  1. PULL_DATA -> PULL_ACK
     Proves bidirectional UDP through the firewall.

  2. PUSH_DATA stat -> PUSH_ACK
     The gateway "checks in" with stats. After this, the gateway with
     this EUI should appear (or update "last seen") in the ChirpStack UI.

  3a. PUSH_DATA join-request -> PUSH_ACK [+ PULL_RESP join-accept]      (default)
      Synthetic LoRaWAN 1.0 Join-Request rxpk. PUSH_ACK proves the
      uplink path; the Join-Accept only comes back with a real MIC, so
      with the default placeholder MIC ChirpStack accepts the frame
      but rejects the join — fine for firewall testing.

  3b. PUSH_DATA data-uplink -> PUSH_ACK                                  (--uplink)
      Real LoRaWAN data uplinks ("up" events in ChirpStack's Events
      tab, with FCnt/FPort like a live device). Needs the device's
      session keys (DevAddr + NwkSKey + AppSKey) and `pycryptodome`:

          pip install pycryptodome

      Get the keys from ChirpStack: the device's *Activation* tab
      (after OTAA) or its *Configuration* tab (ABP). FCnt must be
      strictly greater than the last value ChirpStack has seen, or the
      frame is dropped as a replay (unless "Disable frame-counter
      validation" is on for the device).

Examples:
    # default: pull / stat / synthetic join-request
    python3 chirpstack_gw_sim.py \\
        --host firewall.example.com --udp 1701 \\
        --gateway-eui 0102030405060708

    # send 5 real data uplinks that will appear in Events
    python3 chirpstack_gw_sim.py \\
        --host firewall.example.com --udp 1701 \\
        --gateway-eui 0102030405060708 --uplink \\
        --dev-addr 01020304 \\
        --nwk-skey 00112233445566778899aabbccddeeff \\
        --app-skey ffeeddccbbaa99887766554433221100 \\
        --fport 1 --payload-hex deadbeef --fcnt 100 --count 5

    # provision a new ABP device in ChirpStack, then send 10 demo uplinks
    # (battery + temperature + humidity + random bytes) every 5s
    python3 chirpstack_gw_sim.py \\
        --host firewall.example.com --udp 1701 \\
        --gateway-eui 0102030405060708 \\
        --provision \\
        --cs-api-url http://chirpstack:8080 \\
        --cs-api-token <chirpstack-api-token> \\
        --cs-application-id <app-uuid> \\
        --cs-device-profile-id <abp-profile-uuid> \\
        --dev-eui 90eae2ffffabcdef --device-name sim-001 \\
        --demo-payload --count 10 --uplink-interval 5

    # keep the gateway "online" indefinitely
    python3 chirpstack_gw_sim.py --host ... --udp 1701 --keep-alive
"""
import argparse
import base64
import json
import os
import random
import socket
import struct
import sys
import time
import urllib.error
import urllib.request

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


# --- ChirpStack REST API (device provisioning) ---------------------------
#
# ChirpStack v4 exposes its gRPC API as REST via a JSON gateway, usually on
# port 8080 of the chirpstack server. Auth: a global API token created in
# the ChirpStack UI under your user profile.

def cs_api(method: str, url: str, token: str, body=None,
           timeout: float = 10.0):
    """Call a ChirpStack REST endpoint. Returns (status, parsed_json)."""
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Grpc-Metadata-Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload = r.read()
            return r.status, (json.loads(payload) if payload else {})
    except urllib.error.HTTPError as e:
        payload = e.read()
        try:
            parsed = json.loads(payload) if payload else {}
        except json.JSONDecodeError:
            parsed = {"raw": payload.decode(errors="replace")}
        return e.code, parsed


def provision_device(api_url: str, token: str, app_id: str, dp_id: str,
                     dev_eui: bytes, name: str, dev_addr: bytes,
                     nwk_skey: bytes, app_skey: bytes,
                     skip_fcnt_check: bool = True) -> None:
    """Create + ABP-activate a device in ChirpStack. Idempotent on re-runs:
    if the device already exists the activation is overwritten."""
    base = api_url.rstrip("/")
    eui_hex = dev_eui.hex()

    print(f"-> CS API POST /api/devices  (DevEUI={eui_hex})")
    status, body = cs_api("POST", f"{base}/api/devices", token, {
        "device": {
            "devEui": eui_hex,
            "name": name,
            "description": "Created by chirpstack_gw_sim",
            "applicationId": app_id,
            "deviceProfileId": dp_id,
            "skipFcntCheck": skip_fcnt_check,
            "isDisabled": False,
        }
    })
    if status in (200, 201):
        print(f"   <- {status} device created")
    elif status == 409 or "already exists" in str(body).lower():
        print(f"   <- {status} device exists; will re-activate")
    elif status == 404:
        raise RuntimeError(
            f"create device failed: 404 {body}\n"
            f"  Hint: ChirpStack v4's REST/JSON API runs in the separate "
            f"`chirpstack-rest-api` container on port 8090 by default — not "
            f"on the main chirpstack server's port 8080 (which is gRPC + web "
            f"UI). Try --cs-api-url http://<host>:8090 and verify the "
            f"container is running: `docker ps | grep chirpstack-rest-api`."
        )
    elif status in (401, 403):
        raise RuntimeError(
            f"create device failed: {status} {body}\n"
            f"  Hint: API token is invalid or lacks permission. Make sure "
            f"it's a *global* API key (user menu -> API keys -> Add), not a "
            f"tenant-scoped key without access to this application."
        )
    else:
        raise RuntimeError(f"create device failed: {status} {body}")

    print(f"-> CS API POST /api/devices/{eui_hex}/activate  "
          f"(DevAddr={dev_addr.hex()})")
    status, body = cs_api(
        "POST", f"{base}/api/devices/{eui_hex}/activate", token, {
            "deviceActivation": {
                "devAddr": dev_addr.hex(),
                "appSKey": app_skey.hex(),
                "nwkSEncKey": nwk_skey.hex(),
                "sNwkSIntKey": nwk_skey.hex(),
                "fNwkSIntKey": nwk_skey.hex(),
                "fCntUp": 0,
                "nFCntDown": 0,
                "aFCntDown": 0,
            }
        })
    if status not in (200, 201):
        raise RuntimeError(f"activate device failed: {status} {body}")
    print(f"   <- {status} activated")


# --- Demo payload --------------------------------------------------------

def demo_payload(n_random: int = 4, battery=None):
    """Realistic device payload: battery | temperature | humidity | random.

    Byte layout (big-endian):
        [0]      battery percent (0..100)
        [1:3]    temperature, signed int16, value = °C × 100  (e.g. 2350 = 23.50°C)
        [3:5]    humidity, unsigned int16, value = % × 100
        [5:]     n_random random bytes

    Returns (payload_bytes, decoded_dict) so we can print what we sent.
    """
    bat = random.randint(20, 100) if battery is None else max(0, min(100, battery))
    temp_c = round(random.uniform(15.0, 35.0), 2)
    hum_pct = round(random.uniform(20.0, 80.0), 2)
    rnd = os.urandom(max(0, n_random))
    payload = (
        bytes([bat])
        + struct.pack(">h", int(temp_c * 100))
        + struct.pack(">H", int(hum_pct * 100))
        + rnd
    )
    decoded = {
        "battery_pct": bat,
        "temperature_c": temp_c,
        "humidity_pct": hum_pct,
        "random": rnd.hex(),
    }
    return payload, decoded


# --- LoRaWAN data uplinks ------------------------------------------------
#
# To produce frames ChirpStack will actually accept (and surface as "up"
# events with FCnt/FPort), we need a properly-encrypted FRMPayload + a
# valid AES-CMAC MIC. That needs AES + CMAC primitives, which stdlib
# doesn't ship. pycryptodome is optional: if it isn't installed, the
# --uplink stage refuses to run and the rest of the script still works.

try:
    from Crypto.Cipher import AES                  # type: ignore[import-not-found]
    from Crypto.Hash import CMAC                   # type: ignore[import-not-found]
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


def _aes_block(key: bytes, block: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(block)


def _aes_cmac(key: bytes, data: bytes) -> bytes:
    c = CMAC.new(key, ciphermod=AES)
    c.update(data)
    return c.digest()


def lorawan_payload_cipher(key: bytes, dev_addr_le: bytes, fcnt: int,
                           direction: int, payload: bytes) -> bytes:
    """LoRaWAN FRMPayload AES-128 stream cipher (LoRaWAN 1.0/1.1 §4.3.3.1).

    Generates S_i = AES_ECB(key, A_i) and XORs each block of plaintext
    against S_i. direction is 0 for uplink, 1 for downlink.
    """
    out = bytearray(len(payload))
    n_blocks = (len(payload) + 15) // 16
    for i in range(1, n_blocks + 1):
        a_i = (bytes([0x01, 0, 0, 0, 0, direction]) + dev_addr_le
               + struct.pack("<I", fcnt) + bytes([0x00, i]))
        s_i = _aes_block(key, a_i)
        start = (i - 1) * 16
        for j in range(min(16, len(payload) - start)):
            out[start + j] = payload[start + j] ^ s_i[j]
    return bytes(out)


def lorawan_uplink_mic(nwk_skey: bytes, dev_addr_le: bytes,
                       fcnt: int, msg: bytes) -> bytes:
    """MIC = CMAC(NwkSKey, B0 || MSG)[0:4], uplink direction (LoRaWAN §4.4)."""
    b0 = (bytes([0x49, 0, 0, 0, 0, 0x00]) + dev_addr_le
          + struct.pack("<I", fcnt) + bytes([0x00, len(msg)]))
    return _aes_cmac(nwk_skey, b0 + msg)[:4]


def build_data_up_phy(dev_addr: bytes, nwk_skey: bytes, app_skey: bytes,
                      fcnt: int, fport: int, payload: bytes,
                      confirmed: bool = False, fopts: bytes = b"") -> bytes:
    """Build a LoRaWAN 1.0 Data Up PHYPayload.

    dev_addr: 4 bytes, MSB-first (gets flipped to LE on the wire).
    Encrypts FRMPayload with AppSKey when FPort >= 1, NwkSKey when FPort = 0
    (LoRaWAN MAC commands case).
    fopts: up to 15 bytes of MAC commands piggybacked in the FHDR (FOptsLen
    gets packed into the low 4 bits of FCtrl).
    """
    if len(fopts) > 15:
        raise ValueError("FOpts must be <= 15 bytes (FCtrl.FOptsLen is 4 bits)")
    mhdr = 0x80 if confirmed else 0x40
    dev_addr_le = dev_addr[::-1]
    fctrl = len(fopts) & 0x0F     # FOptsLen in FCtrl's low nibble
    fhdr = (dev_addr_le + bytes([fctrl]) + struct.pack("<H", fcnt & 0xFFFF)
            + fopts)
    key = app_skey if fport >= 1 else nwk_skey
    enc = lorawan_payload_cipher(key, dev_addr_le, fcnt, 0, payload)
    msg = bytes([mhdr]) + fhdr + bytes([fport]) + enc
    mic = lorawan_uplink_mic(nwk_skey, dev_addr_le, fcnt, msg)
    return msg + mic


def build_dev_status_ans(battery_pct, margin_db: int = 7) -> bytes:
    """DevStatusAns MAC command (CID 0x06), placed in FOpts.

    Encodes the LoRaWAN battery byte:
      0           -> external power (overridden if battery_pct is None)
      1..254      -> battery level (1 = ~0%, 254 = ~100%)
      255         -> unknown
    margin_db: signed 6-bit SNR (-32..+31 dB) of the last DevStatusReq.
    """
    if battery_pct is None:
        bat = 255
    else:
        pct = max(0, min(100, int(battery_pct)))
        bat = 1 + (pct * 253) // 100      # 0% -> 1, 100% -> 254
    m = max(-32, min(31, int(margin_db))) & 0x3F
    return bytes([0x06, bat, m])


def stage_data_uplinks(s, addr, gw_eui, dev_addr, nwk_skey, app_skey,
                       fport, payload_factory, start_fcnt, count, freq_mhz,
                       confirmed, interval, include_status=False,
                       status_margin=7, status_battery=None) -> bool:
    """Send `count` data uplinks. payload_factory() must return either
    bytes (the FRMPayload) or (bytes, dict-for-printing).

    When include_status is True, every uplink carries a DevStatusAns MAC
    command in FOpts so ChirpStack also records a 'status' event with
    battery + margin. The battery value comes from status_battery, or
    falls back to the payload's decoded 'battery_pct' (for --demo-payload),
    or 80% if neither is available.
    """
    kind = "Confirmed" if confirmed else "Unconfirmed"
    ok = True
    for i in range(count):
        fcnt = start_fcnt + i
        produced = payload_factory()
        if isinstance(produced, tuple):
            payload, decoded = produced
        else:
            payload, decoded = produced, None

        fopts = b""
        status_suffix = ""
        if include_status:
            if status_battery is not None:
                bat = status_battery
            elif decoded and "battery_pct" in decoded:
                bat = decoded["battery_pct"]
            else:
                bat = 80
            fopts = build_dev_status_ans(bat, status_margin)
            status_suffix = (f"  +status(battery={bat}%, "
                             f"margin={status_margin}dB)")
        phy = build_data_up_phy(dev_addr, nwk_skey, app_skey, fcnt, fport,
                                payload, confirmed, fopts=fopts)
        token = random.randint(0, 0xFFFF)
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
        suffix = f" decoded={decoded}" if decoded else ""
        print(f"-> PUSH_DATA {kind} Data Up FCnt={fcnt} FPort={fport} "
              f"plain={payload.hex()}{suffix}{status_suffix}")
        resp = send_recv(s, addr, pkt, PUSH_ACK)
        if resp is None:
            print(f"   TIMEOUT — no PUSH_ACK for FCnt={fcnt}")
            ok = False
        else:
            print(f"   <- PUSH_ACK ok ({len(phy)}B PHY: {phy.hex()})")
        if i < count - 1 and interval > 0:
            time.sleep(interval)
    if ok:
        print("If frames don't show up in ChirpStack's Events tab:")
        print("  * keys must match — check the device's Activation tab")
        print("  * FCnt must be strictly greater than the last value seen")
        print("    (or disable frame-counter validation on the device)")
        print("  * the device must be activated (ABP, or already-joined OTAA)")
    return ok


# --- end LoRaWAN data uplinks -------------------------------------------


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


def parse_hex_bytes(expected_bytes: int):
    def _parse(s: str) -> bytes:
        clean = s.replace(":", "").replace("-", "").lower()
        want = expected_bytes * 2
        if len(clean) != want or any(c not in "0123456789abcdef" for c in clean):
            raise argparse.ArgumentTypeError(
                f"expected {want} hex chars ({expected_bytes} bytes), got {s!r}"
            )
        return bytes.fromhex(clean)
    return _parse


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
                   help="after the join/uplink stage, loop PULL_DATA every 10s")
    p.add_argument("--keep-alive-interval", type=float, default=10.0)

    g = p.add_argument_group("data uplink (--uplink)",
        "send LoRaWAN data uplinks that ChirpStack will accept and show in "
        "Events. Requires `pip install pycryptodome`.")
    g.add_argument("--uplink", action="store_true",
                   help="run the data-uplink stage instead of the synthetic join-request")
    g.add_argument("--dev-addr", type=parse_hex_bytes(4),
                   help="device address, 8 hex chars (e.g. 01020304)")
    g.add_argument("--nwk-skey", type=parse_hex_bytes(16),
                   help="Network session key, 32 hex chars")
    g.add_argument("--app-skey", type=parse_hex_bytes(16),
                   help="Application session key, 32 hex chars")
    g.add_argument("--fport", type=int, default=1, help="FPort, 1..223 (default 1)")
    g.add_argument("--payload-hex", default="deadbeef",
                   help="fixed FRMPayload bytes as hex (default 'deadbeef'). "
                        "Overridden by --demo-payload.")
    g.add_argument("--demo-payload", action="store_true",
                   help="generate a realistic payload per uplink: "
                        "battery%% | temp(°C×100) | humidity(%%×100) | random bytes")
    g.add_argument("--demo-battery", type=int, default=None,
                   help="fix the battery byte (0..100) instead of randomizing")
    g.add_argument("--demo-random-bytes", type=int, default=4,
                   help="number of trailing random bytes in --demo-payload (default 4)")
    g.add_argument("--fcnt", type=int, default=0, help="starting FCntUp (default 0)")
    g.add_argument("--count", type=int, default=1,
                   help="number of uplinks to send (FCnt increments)")
    g.add_argument("--confirmed", action="store_true",
                   help="send Confirmed Data Up (MHDR=0x80) instead of Unconfirmed")
    g.add_argument("--uplink-interval", type=float, default=2.0,
                   help="seconds between uplinks (default 2)")
    g.add_argument("--status", action="store_true",
                   help="include a DevStatusAns MAC command in every uplink, so "
                        "ChirpStack also records a 'status' event (battery + "
                        "margin) for each frame.")
    g.add_argument("--status-margin", type=int, default=7,
                   help="margin (SNR in dB, -32..+31) reported in DevStatusAns "
                        "(default 7)")
    g.add_argument("--status-battery", type=int, default=None,
                   help="fix the battery percent reported in DevStatusAns. "
                        "Default: use the demo payload's battery (if "
                        "--demo-payload), else 80.")

    pg = p.add_argument_group("provisioning (--provision)",
        "create + ABP-activate a device in ChirpStack via its REST API "
        "before sending uplinks. Implies --uplink.")
    pg.add_argument("--provision", action="store_true",
                    help="create the device in ChirpStack before the uplink stage")
    pg.add_argument("--cs-api-url", help="ChirpStack REST base, e.g. http://chirpstack:8080")
    pg.add_argument("--cs-api-token", help="ChirpStack global API token")
    pg.add_argument("--cs-application-id",
                    help="UUID of the ChirpStack application to add the device to")
    pg.add_argument("--cs-device-profile-id",
                    help="UUID of an ABP device profile to use")
    pg.add_argument("--device-name", default=None,
                    help="device name (default: sim-<deveui>)")

    args = p.parse_args()

    # --provision implies --uplink (no point provisioning without sending).
    if args.provision:
        for flag, val in [("--cs-api-url", args.cs_api_url),
                          ("--cs-api-token", args.cs_api_token),
                          ("--cs-application-id", args.cs_application_id),
                          ("--cs-device-profile-id", args.cs_device_profile_id)]:
            if not val:
                print(f"ERROR: --provision requires {flag}", file=sys.stderr)
                sys.exit(2)
        # Fill any missing crypto with random material so we have a complete
        # ABP session to install on the device.
        if args.dev_addr is None:
            args.dev_addr = os.urandom(4)
        if args.nwk_skey is None:
            args.nwk_skey = os.urandom(16)
        if args.app_skey is None:
            args.app_skey = os.urandom(16)
        name = args.device_name or f"sim-{args.dev_eui.hex()}"
        print(f"provisioning device in ChirpStack:")
        print(f"  DevEUI:  {args.dev_eui.hex()}   name: {name}")
        print(f"  DevAddr: {args.dev_addr.hex()}")
        print(f"  NwkSKey: {args.nwk_skey.hex()}")
        print(f"  AppSKey: {args.app_skey.hex()}")
        try:
            provision_device(
                args.cs_api_url, args.cs_api_token,
                args.cs_application_id, args.cs_device_profile_id,
                args.dev_eui, name,
                args.dev_addr, args.nwk_skey, args.app_skey,
            )
        except Exception as e:
            print(f"ERROR: provisioning failed: {e}", file=sys.stderr)
            sys.exit(1)
        # After provisioning we know FCntUp = 0 server-side, so start from 0
        # unless the user explicitly asked otherwise.
        if args.fcnt == 0:
            pass  # already 0
        args.uplink = True

    payload_factory = None
    if args.uplink:
        if not HAVE_CRYPTO:
            print("ERROR: --uplink needs pycryptodome:  pip install pycryptodome",
                  file=sys.stderr)
            sys.exit(2)
        missing = [n for n in ("dev_addr", "nwk_skey", "app_skey")
                   if getattr(args, n) is None]
        if missing:
            print(f"ERROR: --uplink requires --{', --'.join(m.replace('_','-') for m in missing)}",
                  file=sys.stderr)
            sys.exit(2)
        if args.demo_payload:
            payload_factory = lambda: demo_payload(
                n_random=args.demo_random_bytes, battery=args.demo_battery)
        else:
            try:
                fixed = bytes.fromhex(
                    args.payload_hex.replace(":", "").replace("-", ""))
            except ValueError as e:
                print(f"ERROR: --payload-hex invalid: {e}", file=sys.stderr)
                sys.exit(2)
            payload_factory = lambda: fixed
        # --uplink replaces the synthetic Join-Request stage
        args.skip_joinreq = True

    addr = (args.host, args.udp)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    if not stage_pull_data(s, addr, args.gateway_eui):
        sys.exit(1)

    if not args.skip_stat:
        stage_push_stat(s, addr, args.gateway_eui)

    if args.uplink:
        stage_data_uplinks(s, addr, args.gateway_eui,
                           args.dev_addr, args.nwk_skey, args.app_skey,
                           args.fport, payload_factory, args.fcnt, args.count,
                           args.freq, args.confirmed, args.uplink_interval,
                           include_status=args.status,
                           status_margin=args.status_margin,
                           status_battery=args.status_battery)
    elif not args.skip_joinreq:
        stage_join_request(s, addr, args.gateway_eui, args.dev_eui,
                           args.join_eui, args.freq, args.join_listen)

    if args.keep_alive:
        keep_alive_loop(s, addr, args.gateway_eui, args.keep_alive_interval)


if __name__ == "__main__":
    main()
