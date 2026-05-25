# Password Manager (Flask)

A small Flask web application for securely storing, searching, updating, revealing, and deleting passwords.

## Features
- User registration and login
- Password hashing with PBKDF2-HMAC-SHA256
- Per-user vault file
- AES-GCM encryption for each saved password
- AES-GCM encryption of the vault file on logout / app close
- Search by title
- Update and delete entries
- Random password generator
- Copy password to clipboard after reveal

## Data storage
Each user gets a separate vault stored in:

- `storage/users/<username>/vault.csv`
- `storage/users/<username>/vault.csv.aes`

The CSV contains:


- Title
- EncryptedPassword
- URL
- Notes

## Run
```bash
pip install -r requirements.txt
python app.py
```

Open:

```text
http://127.0.0.1:5000
```


