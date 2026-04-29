#!/usr/bin/env python3
"""
Navegation hardening/setup helper (Tor + OpenVPN).

Uso:
  python3 navegation.py --dry-run
  sudo python3 navegation.py
"""

from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import shutil
import subprocess
import sys

TORRC = pathlib.Path("/etc/tor/torrc")
OPENVPN_SERVER_CONF = pathlib.Path("/etc/openvpn/server.conf")

TOR_REQUIRED_LINES = [
    "VirtualAddrNetwork 10.192.0.0/10",
    "AutomapHostsOnResolve 1",
    "TransPort 9050",
    "DNSPort 53",
]

OPENVPN_TEMPLATE = """server 10.8.0.0 255.255.255.0
dev tun
proto udp
topology subnet
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 10.8.0.1"
keepalive 10 120
cipher AES-256-CBC
auth SHA256
persist-key
persist-tun
verb 3
"""


def run(cmd: list[str], dry_run: bool) -> None:
    line = " ".join(cmd)
    print(f"[cmd] {line}")
    if dry_run:
        return
    subprocess.run(cmd, check=True)


def backup_file(path: pathlib.Path, dry_run: bool) -> None:
    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = path.with_suffix(path.suffix + f".bak.{ts}")
    print(f"[backup] {path} -> {backup}")
    if dry_run:
        return
    shutil.copy2(path, backup)


def ensure_root(dry_run: bool) -> None:
    if dry_run:
        return
    if hasattr(pathlib, "os") and pathlib.os.geteuid() != 0:
        raise PermissionError("Executa como root (sudo) ou usa --dry-run.")


def ensure_packages(dry_run: bool) -> None:
    run(["apt-get", "update"], dry_run)
    run(["apt-get", "install", "-y", "tor", "openvpn"], dry_run)


def update_torrc(dry_run: bool) -> None:
    if not TORRC.exists():
        raise FileNotFoundError(f"torrc não encontrado: {TORRC}")
    content = TORRC.read_text(encoding="utf-8", errors="ignore")
    missing = [line for line in TOR_REQUIRED_LINES if line not in content]
    if not missing:
        print("[ok] torrc já contém as linhas necessárias.")
        return
    backup_file(TORRC, dry_run)
    print(f"[edit] adicionando {len(missing)} linha(s) no {TORRC}")
    if dry_run:
        return
    with TORRC.open("a", encoding="utf-8") as f:
        f.write("\n# Added by navegation.py\n")
        for line in missing:
            f.write(f"{line}\n")


def write_openvpn_conf(dry_run: bool) -> None:
    if OPENVPN_SERVER_CONF.exists():
        backup_file(OPENVPN_SERVER_CONF, dry_run)
    print(f"[write] {OPENVPN_SERVER_CONF}")
    if dry_run:
        return
    OPENVPN_SERVER_CONF.parent.mkdir(parents=True, exist_ok=True)
    OPENVPN_SERVER_CONF.write_text(OPENVPN_TEMPLATE, encoding="utf-8")


def restart_services(dry_run: bool) -> None:
    run(["systemctl", "restart", "tor"], dry_run)
    run(["systemctl", "enable", "--now", "openvpn@server"], dry_run)


def main() -> int:
    parser = argparse.ArgumentParser(description="Setup Tor + OpenVPN com idempotência.")
    parser.add_argument("--dry-run", action="store_true", help="Mostra ações sem alterar o sistema")
    args = parser.parse_args()
    try:
        ensure_root(args.dry_run)
        ensure_packages(args.dry_run)
        update_torrc(args.dry_run)
        write_openvpn_conf(args.dry_run)
        restart_services(args.dry_run)
        print("[done] Navegation concluído com sucesso.")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"[erro] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
