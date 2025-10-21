# create_user.py
import argparse
import getpass
import sqlite3
import os
from datetime import datetime
from werkzeug.security import generate_password_hash

DB_PATH = os.environ.get("HONEYPOT_DB", "./honeypot.db")

def create_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)")
        pw_hash = generate_password_hash(password)
        cur.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)", (username, pw_hash, datetime.utcnow().isoformat() + "Z"))
        conn.commit()
        print(f"User '{username}' created.")
    except sqlite3.IntegrityError:
        print(f"Error: user '{username}' already exists.")
    except Exception as e:
        print("Error creating user:", e)
    finally:
        conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a honeypot user in the local SQLite DB")
    parser.add_argument("--username", "-u", help="username to create", required=True)
    parser.add_argument("--password", "-p", help="password to set (warning: shows in shell). If omitted you will be prompted.", required=False)
    args = parser.parse_args()

    if args.password:
        pwd = args.password
    else:
        pwd = getpass.getpass(f"Password for {args.username}: ")
        pwd2 = getpass.getpass("Repeat password: ")
        if pwd != pwd2:
            print("Passwords do not match. Aborting.")
            exit(1)

    create_user(args.username, pwd)
