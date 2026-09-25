"""Account management from the command line.

    python -m app.cli adduser <username> [--admin]
    python -m app.cli passwd <username>
    python -m app.cli reset-2fa <username>
    python -m app.cli list
"""

import argparse
import getpass
import sys

from . import db
from .main import create_user
from .security import hash_password


def read_password() -> str:
    p1 = getpass.getpass("Şifre: ")
    p2 = getpass.getpass("Şifre (tekrar): ")
    if p1 != p2:
        sys.exit("Şifreler eşleşmiyor")
    if len(p1) < 8:
        sys.exit("Şifre en az 8 karakter olmalı")
    return p1


def main() -> None:
    ap = argparse.ArgumentParser(prog="app.cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("adduser")
    a.add_argument("username")
    a.add_argument("--admin", action="store_true")
    sub.add_parser("passwd").add_argument("username")
    sub.add_parser("reset-2fa").add_argument("username")
    sub.add_parser("list")
    args = ap.parse_args()

    db.init()
    c = db.conn()
    if args.cmd == "adduser":
        create_user(args.username, read_password(), is_admin=args.admin)
        print("Hesap oluşturuldu:", args.username)
    elif args.cmd == "passwd":
        cur = c.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (hash_password(read_password()), args.username),
        )
        if cur.rowcount == 0:
            sys.exit("Böyle bir hesap yok")
        c.execute(
            "DELETE FROM tokens WHERE user_id = (SELECT id FROM users WHERE username = ?)",
            (args.username,),
        )
        print("Şifre değişti, tüm oturumlar kapatıldı")
    elif args.cmd == "reset-2fa":
        cur = c.execute("UPDATE users SET totp_secret = NULL WHERE username = ?", (args.username,))
        if cur.rowcount == 0:
            sys.exit("Böyle bir hesap yok")
        print("İki adımlı doğrulama kapatıldı")
    elif args.cmd == "list":
        for u in c.execute(
            "SELECT u.username, u.is_admin, (SELECT COUNT(*) FROM devices d WHERE d.user_id = u.id) n "
            "FROM users u ORDER BY u.username"
        ):
            print(f"{u['username']}{' (admin)' if u['is_admin'] else ''}: {u['n']} cihaz")


if __name__ == "__main__":
    main()
