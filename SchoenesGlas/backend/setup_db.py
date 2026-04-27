"""
Datenbank-Einrichtungsskript – SchönesGlas Mitarbeiterportal
Erstellt die SQLite-Datenbank und die Tabelle 'workers'.

E-Mail-Format: sg{Personalnummer}@SchoenesGlas.optik
Beispiel:       sg1042@SchoenesGlas.optik  (Personalnummer = 1042)

Verwendung:
    python3 setup_db.py
"""
import os
import re
import sqlite3
from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), "workers.db")

# Regex: E-Mail muss mindestens eine Ziffer enthalten (= Personalnummer)
_EMAIL_RE = re.compile(r"^[a-zA-Z]+\d+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def validate_email(email: str) -> bool:
    """E-Mail muss Buchstaben + Personalnummer + Domain enthalten."""
    return bool(_EMAIL_RE.match(email))


def setup() -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # ── Tabelle anlegen ────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS workers (
            id         INTEGER  PRIMARY KEY AUTOINCREMENT,
            login      TEXT     NOT NULL UNIQUE,
            password   TEXT     NOT NULL,
            email      TEXT     NOT NULL UNIQUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ── Demo-Mitarbeiter ───────────────────────────────────────────────────────
    # E-Mail-Konvention: sg{Personalnummer}@SchoenesGlas.optik
    demo_workers = [
        ("SG-1001", "Passwort123!", "sg1001@SchoenesGlas.optik"),
        ("SG-1042", "Passwort123!", "sg1042@SchoenesGlas.optik"),
    ]

    print(f"Datenbank: {DB_PATH}")
    print("-" * 60)

    for login, plain_pw, email in demo_workers:
        if not validate_email(email):
            print(f"  FEHLER: Ungültiges E-Mail-Format für {login}: {email}")
            print("          Format muss sein: sg{Personalnummer}@Domain.tld")
            continue
        try:
            c.execute(
                "INSERT INTO workers (login, password, email) VALUES (?, ?, ?)",
                (login, generate_password_hash(plain_pw), email),
            )
            print(f"  ✓ Angelegt: {login:12} | {email:35} | Passwort: {plain_pw}")
        except sqlite3.IntegrityError:
            print(f"  – Übersprungen (bereits vorhanden): {login}")

    conn.commit()
    conn.close()
    print("-" * 60)
    print("Fertig. Starte die App mit:  python3 app.py")
    print("Dann öffnen:                 http://127.0.0.1:5000")


if __name__ == "__main__":
    setup()
