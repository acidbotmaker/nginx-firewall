import getpass
import secrets
import sys

import typer

from .auth import set_admin_password
from .db import init_db
from .tokens import create_token, delete_token, list_tokens

app = typer.Typer(help="nginx-firewall admin CLI")


@app.command("reset-password")
def reset_password(
    password: str = typer.Option(None, "--password", help="New password (interactive prompt if omitted)"),
    random: bool = typer.Option(False, "--random", help="Generate a random password and print it"),
):
    """Set or reset the admin password."""
    init_db()
    if random:
        pw = secrets.token_urlsafe(16)
        set_admin_password(pw)
        typer.echo(f"New admin password: {pw}")
        return
    if password is None:
        pw = getpass.getpass("New password: ")
        confirm = getpass.getpass("Confirm: ")
        if pw != confirm:
            typer.echo("Passwords do not match", err=True)
            raise typer.Exit(code=1)
    else:
        pw = password
    if len(pw) < 8:
        typer.echo("Password must be at least 8 characters", err=True)
        raise typer.Exit(code=1)
    set_admin_password(pw)
    typer.echo("Admin password updated.")


@app.command("list-tokens")
def cli_list_tokens():
    """List API tokens (metadata only)."""
    init_db()
    rows = list_tokens()
    if not rows:
        typer.echo("(no tokens)")
        return
    for t in rows:
        typer.echo(
            f"{t['id']:>4}  {t['name']:<32}  created={t['created_at']}  last_used={t['last_used_at'] or '—'}"
        )


@app.command("create-token")
def cli_create_token(name: str):
    """Create an API token; the plaintext is printed once."""
    init_db()
    token, row = create_token(name)
    typer.echo(f"id={row['id']} name={row['name']}")
    typer.echo(f"token: {token}")


@app.command("revoke-token")
def cli_revoke_token(token_id: int):
    """Revoke an API token by id."""
    init_db()
    if not delete_token(token_id):
        typer.echo("Not found", err=True)
        raise typer.Exit(code=1)
    typer.echo("Revoked.")


if __name__ == "__main__":
    app()
