from __future__ import annotations

import atexit
import base64
import csv
import hashlib
import json
import os
import secrets
import shutil
import string
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


APP_ROOT = Path(__file__).resolve().parent
DATA_DIR = APP_ROOT / "storage"
USERS_DIR = DATA_DIR / "users"
USERS_FILE = DATA_DIR / "users.json"
HEADER = ["ID", "Title", "EncryptedPassword", "URL", "Notes"]

PBKDF2_ITERATIONS = 200_000
AES_NONCE_SIZE = 12
AES_KEY_SIZE = 32

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key-change-me")

# Active decrypted vault keys for logged-in users (local classroom demo only).
ACTIVE_KEYS: Dict[str, bytes] = {}


@dataclass
class VaultEntry:
    id: str
    title: str
    encrypted_password: str
    url: str
    notes: str


def ensure_storage() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    USERS_DIR.mkdir(parents=True, exist_ok=True)
    if not USERS_FILE.exists():
        USERS_FILE.write_text(json.dumps({}, indent=2), encoding="utf-8")


def load_users() -> Dict[str, dict]:
    ensure_storage()
    try:
        return json.loads(USERS_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def save_users(users: Dict[str, dict]) -> None:
    USERS_FILE.write_text(json.dumps(users, indent=2), encoding="utf-8")


def user_dir(username: str) -> Path:
    return USERS_DIR / username


def vault_plain_path(username: str) -> Path:
    return user_dir(username) / "vault.csv"


def vault_encrypted_path(username: str) -> Path:
    return user_dir(username) / "vault.csv.aes"


def user_meta_path(username: str) -> Path:
    return user_dir(username) / "meta.json"


def derive_key(password: str, salt_b64: str) -> bytes:
    salt = base64.b64decode(salt_b64)
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=AES_KEY_SIZE,
    )


def create_password_record(password: str, key: bytes) -> str:
    nonce = secrets.token_bytes(AES_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, password.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("ascii")


def reveal_password(record: str, key: bytes) -> str:
    raw = base64.b64decode(record)
    nonce, ct = raw[:AES_NONCE_SIZE], raw[AES_NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode("utf-8")


def encrypt_bytes(data: bytes, key: bytes) -> str:
    nonce = secrets.token_bytes(AES_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, data, None)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt_bytes(token_b64: str, key: bytes) -> bytes:
    raw = base64.b64decode(token_b64)
    nonce, ct = raw[:AES_NONCE_SIZE], raw[AES_NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


def create_empty_vault(username: str) -> None:
    user_dir(username).mkdir(parents=True, exist_ok=True)
    plain = vault_plain_path(username)
    if not plain.exists():
        with plain.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(HEADER)


def encrypt_vault_file(username: str) -> None:
    key = ACTIVE_KEYS.get(username)
    if not key:
        return
    plain = vault_plain_path(username)
    if not plain.exists():
        return
    encrypted = encrypt_bytes(plain.read_bytes(), key)
    vault_encrypted_path(username).write_text(encrypted, encoding="utf-8")


def remove_plaintext_vault(username: str) -> None:
    plain = vault_plain_path(username)
    try:
        if plain.exists():
            plain.unlink()
    except Exception:
        pass


def decrypt_vault_file(username: str, key: bytes) -> None:
    udir = user_dir(username)
    udir.mkdir(parents=True, exist_ok=True)
    plain = vault_plain_path(username)
    enc = vault_encrypted_path(username)

    if not enc.exists():
        create_empty_vault(username)
        encrypt_bytes(plain.read_bytes(), key)
        encrypt_vault_file(username)
        return

    decrypted = decrypt_bytes(enc.read_text(encoding="utf-8"), key)
    plain.write_bytes(decrypted)


def read_entries(username: str) -> List[VaultEntry]:
    path = vault_plain_path(username)
    if not path.exists():
        create_empty_vault(username)
    entries: List[VaultEntry] = []
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get("ID"):
                continue
            entries.append(
                VaultEntry(
                    id=row.get("ID", ""),
                    title=row.get("Title", ""),
                    encrypted_password=row.get("EncryptedPassword", ""),
                    url=row.get("URL", ""),
                    notes=row.get("Notes", ""),
                )
            )
    return entries


def write_entries(username: str, entries: List[VaultEntry]) -> None:
    path = vault_plain_path(username)
    create_empty_vault(username)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        for entry in entries:
            writer.writerow([entry.id, entry.title, entry.encrypted_password, entry.url, entry.notes])
    encrypt_vault_file(username)


def current_username() -> Optional[str]:
    return session.get("username")


def current_key() -> Optional[bytes]:
    username = current_username()
    if not username:
        return None
    return ACTIVE_KEYS.get(username)


def require_login() -> Optional[str]:
    username = current_username()
    if not username:
        flash("Please log in first.", "warning")
        return None
    if username not in ACTIVE_KEYS:
        flash("Session expired. Please log in again.", "warning")
        session.pop("username", None)
        return None
    return username


def sanitize_text(value: str) -> str:
    return (value or "").strip()


def find_entry(entries: List[VaultEntry], entry_id: str) -> Optional[VaultEntry]:
    for entry in entries:
        if entry.id == entry_id:
            return entry
    return None


def register_user(username: str, password: str) -> Optional[str]:
    username = sanitize_text(username)
    if not username or not password:
        return "Username and password are required."

    users = load_users()
    if username in users:
        return "That username is already taken."

    salt = secrets.token_bytes(16)
    salt_b64 = base64.b64encode(salt).decode("ascii")
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=AES_KEY_SIZE,
    )

    users[username] = {
        "salt": salt_b64,
        "password_hash": base64.b64encode(derived).decode("ascii"),
    }
    save_users(users)
    create_empty_vault(username)
    encrypt_vault_file_after_register(username, derived)
    user_dir(username).mkdir(parents=True, exist_ok=True)
    user_meta_path(username).write_text(
        json.dumps({"created": True}, indent=2), encoding="utf-8"
    )
    return None


def encrypt_vault_file_after_register(username: str, key: bytes) -> None:
    ACTIVE_KEYS[username] = key
    encrypt_vault_file(username)
    remove_plaintext_vault(username)
    ACTIVE_KEYS.pop(username, None)


@app.route("/")
def index():
    if current_username():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        error = register_user(request.form.get("username", ""), request.form.get("password", ""))
        if error:
            flash(error, "danger")
            return render_template("register.html")
        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = sanitize_text(request.form.get("username", ""))
        password = request.form.get("password", "")
        users = load_users()
        user = users.get(username)
        if not user:
            flash("Invalid username or password.", "danger")
            return render_template("login.html")

        key = derive_key(password, user["salt"])
        expected = base64.b64decode(user["password_hash"])
        if not secrets.compare_digest(key, expected):
            flash("Invalid username or password.", "danger")
            return render_template("login.html")

        ACTIVE_KEYS[username] = key
        session["username"] = username
        decrypt_vault_file(username, key)
        flash("Login successful.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    username = current_username()
    if username:
        encrypt_vault_file(username)
        remove_plaintext_vault(username)
        ACTIVE_KEYS.pop(username, None)
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    query = sanitize_text(request.args.get("q", ""))
    entries = read_entries(username)
    if query:
        entries = [entry for entry in entries if query.lower() in entry.title.lower()]

    return render_template(
        "dashboard.html",
        username=username,
        entries=entries,
        query=query,
        total=len(read_entries(username)),
    )


@app.route("/add", methods=["GET", "POST"])
def add_entry():
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    if request.method == "POST":
        key = current_key()
        if not key:
            flash("Session expired.", "warning")
            return redirect(url_for("login"))

        title = sanitize_text(request.form.get("title", ""))
        password = request.form.get("password", "")
        url = sanitize_text(request.form.get("url", ""))
        notes = sanitize_text(request.form.get("notes", ""))

        if not title or not password:
            flash("Title and password are required.", "danger")
            return render_template("add_edit.html", mode="add", entry=None)

        entries = read_entries(username)
        entries.append(
            VaultEntry(
                id=str(uuid.uuid4()),
                title=title,
                encrypted_password=create_password_record(password, key),
                url=url,
                notes=notes,
            )
        )
        write_entries(username, entries)
        flash("Password entry added.", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_edit.html", mode="add", entry=None)


@app.route("/edit/<entry_id>", methods=["GET", "POST"])
def edit_entry(entry_id: str):
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    key = current_key()
    if not key:
        flash("Session expired.", "warning")
        return redirect(url_for("login"))

    entries = read_entries(username)
    entry = find_entry(entries, entry_id)
    if not entry:
        flash("Entry not found.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        title = sanitize_text(request.form.get("title", ""))
        password = request.form.get("password", "")
        url = sanitize_text(request.form.get("url", ""))
        notes = sanitize_text(request.form.get("notes", ""))

        if not title:
            flash("Title is required.", "danger")
            return render_template("add_edit.html", mode="edit", entry=entry)

        entry.title = title
        entry.url = url
        entry.notes = notes
        if password:
            entry.encrypted_password = create_password_record(password, key)

        write_entries(username, entries)
        flash("Password entry updated.", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_edit.html", mode="edit", entry=entry)


@app.route("/delete/<entry_id>", methods=["POST"])
def delete_entry(entry_id: str):
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    entries = read_entries(username)
    new_entries = [entry for entry in entries if entry.id != entry_id]
    if len(new_entries) == len(entries):
        flash("Entry not found.", "danger")
    else:
        write_entries(username, new_entries)
        flash("Password entry deleted.", "success")
    return redirect(url_for("dashboard"))


@app.route("/reveal/<entry_id>")
def reveal(entry_id: str):
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    key = current_key()
    if not key:
        flash("Session expired.", "warning")
        return redirect(url_for("login"))

    entries = read_entries(username)
    entry = find_entry(entries, entry_id)
    if not entry:
        flash("Entry not found.", "danger")
        return redirect(url_for("dashboard"))

    password = reveal_password(entry.encrypted_password, key)
    return render_template("reveal.html", entry=entry, password=password)


@app.route("/generate-password")
def generate_password():
    length = int(request.args.get("length", 16))
    length = max(8, min(length, 64))
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    password = "".join(secrets.choice(alphabet) for _ in range(length))
    return {"password": password}


@app.context_processor
def inject_globals():
    return {"logged_in": bool(current_username())}


@atexit.register
def close_open_vaults() -> None:
    for username in list(ACTIVE_KEYS.keys()):
        try:
            encrypt_vault_file(username)
            remove_plaintext_vault(username)
        except Exception:
            pass


if __name__ == "__main__":
    ensure_storage()
    app.run(debug=True)
