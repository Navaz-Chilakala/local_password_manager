"""
Password Manager Backend API
FastAPI backend for the password manager with all encryption and database logic.
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List
import sqlite3
import secrets
import string
import hashlib
import base64
import os
import json
import re
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

app = FastAPI(title="Password Manager API")

# CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files from frontend build
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "frontend", "dist")

# Database path - use /tmp on Render for persistence
if os.environ.get("RENDER"):
    DB_PATH = "/tmp/passwords.db"
else:
    DB_PATH = "passwords.db"

# Default categories
DEFAULT_CATEGORIES = [
    "Social Media", "Banking", "Work", "Shopping",
    "Entertainment", "Email", "Gaming", "Other"
]

# Service icons
SERVICE_ICONS = {
    "google": "🔍", "gmail": "📧", "facebook": "📘", "twitter": "🐦",
    "instagram": "📷", "linkedin": "💼", "github": "🐙", "amazon": "📦",
    "netflix": "🎬", "spotify": "🎵", "apple": "🍎", "microsoft": "🪟",
    "paypal": "💳", "bank": "🏦", "steam": "🎮", "discord": "💬",
    "slack": "💬", "dropbox": "📁", "reddit": "🔴", "youtube": "▶️",
}

# Session storage (in production, use proper session management)
sessions = {}

# Pydantic models
class SetupRequest(BaseModel):
    master_password: str

class LoginRequest(BaseModel):
    master_password: str

class PasswordEntry(BaseModel):
    service: str
    username: str
    password: str
    notes: Optional[str] = ""
    category_id: Optional[int] = None
    two_factor_codes: Optional[List[str]] = None

class PasswordUpdate(BaseModel):
    service: str
    username: str
    password: str
    notes: Optional[str] = ""
    category_id: Optional[int] = None

class CategoryCreate(BaseModel):
    name: str

class SettingUpdate(BaseModel):
    key: str
    value: str

class ExportRequest(BaseModel):
    export_password: str

class ImportRequest(BaseModel):
    import_password: str
    data: str  # base64 encoded

class TwoFactorCodes(BaseModel):
    codes: List[str]


# Helper functions
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def get_session_cipher(session_id: str):
    if session_id not in sessions:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return sessions[session_id]

def get_service_icon(service: str) -> str:
    service_lower = service.lower()
    for key, icon in SERVICE_ICONS.items():
        if key in service_lower:
            return icon
    return "🔑"

def calculate_password_strength(password: str) -> dict:
    if not password:
        return {"score": 0, "label": "Empty", "color": "#dc3545"}

    score = 0
    length = len(password)

    if length >= 8: score += 20
    if length >= 12: score += 15
    if length >= 16: score += 10
    if length >= 20: score += 5

    if re.search(r'[a-z]', password): score += 10
    if re.search(r'[A-Z]', password): score += 15
    if re.search(r'[0-9]', password): score += 15
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): score += 20

    if re.search(r'(.)\1{2,}', password): score -= 10
    if re.search(r'(012|123|234|345|456|567|678|789)', password): score -= 10

    score = max(0, min(100, score))

    if score < 25:
        return {"score": score, "label": "Weak", "color": "#dc3545"}
    elif score < 50:
        return {"score": score, "label": "Fair", "color": "#ffc107"}
    elif score < 75:
        return {"score": score, "label": "Good", "color": "#17a2b8"}
    else:
        return {"score": score, "label": "Strong", "color": "#28a745"}


# API Endpoints

@app.get("/api/status")
def get_status():
    """Check if database exists and is initialized."""
    exists = os.path.exists(DB_PATH)
    if exists:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM config WHERE key = 'master_hash'")
        result = cursor.fetchone()
        conn.close()
        return {"initialized": result is not None, "database_exists": True}
    return {"initialized": False, "database_exists": False}


@app.post("/api/setup")
def setup(request: SetupRequest):
    """Initialize the password manager with a master password."""
    if len(request.master_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    salt = os.urandom(16)
    conn = get_db()
    cursor = conn.cursor()

    # Create tables
    cursor.execute('''CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS categories (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL)''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            encrypted_password TEXT NOT NULL,
            notes TEXT,
            category_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (category_id) REFERENCES categories(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_id INTEGER NOT NULL,
            encrypted_password TEXT NOT NULL,
            changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (password_id) REFERENCES passwords(id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS two_factor_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_id INTEGER NOT NULL,
            encrypted_codes TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (password_id) REFERENCES passwords(id) ON DELETE CASCADE
        )
    ''')

    # Insert default categories
    for category in DEFAULT_CATEGORIES:
        cursor.execute('INSERT OR IGNORE INTO categories (name) VALUES (?)', (category,))

    # Save config
    cursor.execute('INSERT OR REPLACE INTO config VALUES (?, ?)', ('salt', base64.b64encode(salt).decode()))
    cursor.execute('INSERT OR REPLACE INTO config VALUES (?, ?)', ('master_hash', hash_password(request.master_password)))
    cursor.execute('INSERT OR REPLACE INTO config VALUES (?, ?)', ('theme', 'light'))
    cursor.execute('INSERT OR REPLACE INTO config VALUES (?, ?)', ('auto_lock_minutes', '5'))
    cursor.execute('INSERT OR REPLACE INTO config VALUES (?, ?)', ('password_expiry_days', '90'))

    conn.commit()
    conn.close()

    return {"success": True, "message": "Password manager initialized"}


@app.post("/api/login")
def login(request: LoginRequest):
    """Authenticate and create a session."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT value FROM config WHERE key = 'salt'")
    salt_row = cursor.fetchone()
    cursor.execute("SELECT value FROM config WHERE key = 'master_hash'")
    hash_row = cursor.fetchone()
    conn.close()

    if not salt_row or not hash_row:
        raise HTTPException(status_code=400, detail="Database not initialized")

    if hash_password(request.master_password) != hash_row['value']:
        raise HTTPException(status_code=401, detail="Incorrect password")

    # Create session
    salt = base64.b64decode(salt_row['value'])
    key = derive_key(request.master_password, salt)
    cipher = Fernet(key)

    session_id = secrets.token_hex(32)
    sessions[session_id] = cipher

    return {"success": True, "session_id": session_id}


@app.post("/api/logout")
def logout(session_id: str):
    """Logout and destroy session."""
    if session_id in sessions:
        del sessions[session_id]
    return {"success": True}


@app.get("/api/passwords")
def get_passwords(session_id: str):
    """Get all passwords."""
    cipher = get_session_cipher(session_id)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT p.id, p.service, p.username, p.encrypted_password, p.notes,
               p.created_at, p.updated_at, c.name as category, p.category_id
        FROM passwords p
        LEFT JOIN categories c ON p.category_id = c.id
        ORDER BY p.service
    ''')

    results = []
    for row in cursor.fetchall():
        try:
            decrypted_password = cipher.decrypt(row['encrypted_password'].encode()).decode()
            results.append({
                "id": row['id'],
                "service": row['service'],
                "username": row['username'],
                "password": decrypted_password,
                "notes": row['notes'] or "",
                "created_at": row['created_at'],
                "updated_at": row['updated_at'],
                "category": row['category'] or "Other",
                "category_id": row['category_id'],
                "icon": get_service_icon(row['service'])
            })
        except:
            pass

    conn.close()
    return {"passwords": results}


@app.post("/api/passwords")
def add_password(entry: PasswordEntry, session_id: str):
    """Add a new password."""
    cipher = get_session_cipher(session_id)
    encrypted_password = cipher.encrypt(entry.password.encode()).decode()

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO passwords (service, username, encrypted_password, notes, category_id)
        VALUES (?, ?, ?, ?, ?)
    ''', (entry.service, entry.username, encrypted_password, entry.notes, entry.category_id))

    password_id = cursor.lastrowid

    # Add to history
    cursor.execute('''
        INSERT INTO password_history (password_id, encrypted_password)
        VALUES (?, ?)
    ''', (password_id, encrypted_password))

    # Save 2FA codes if provided
    if entry.two_factor_codes:
        encrypted_codes = cipher.encrypt(json.dumps(entry.two_factor_codes).encode()).decode()
        cursor.execute('''
            INSERT INTO two_factor_codes (password_id, encrypted_codes)
            VALUES (?, ?)
        ''', (password_id, encrypted_codes))

    conn.commit()
    conn.close()

    return {"success": True, "id": password_id}


@app.put("/api/passwords/{password_id}")
def update_password(password_id: int, entry: PasswordUpdate, session_id: str):
    """Update a password."""
    cipher = get_session_cipher(session_id)
    encrypted_password = cipher.encrypt(entry.password.encode()).decode()

    conn = get_db()
    cursor = conn.cursor()

    # Get old password
    cursor.execute('SELECT encrypted_password FROM passwords WHERE id = ?', (password_id,))
    old_row = cursor.fetchone()

    cursor.execute('''
        UPDATE passwords
        SET service = ?, username = ?, encrypted_password = ?, notes = ?,
            category_id = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (entry.service, entry.username, encrypted_password, entry.notes, entry.category_id, password_id))

    # Add to history if password changed
    if old_row and old_row['encrypted_password'] != encrypted_password:
        cursor.execute('''
            INSERT INTO password_history (password_id, encrypted_password)
            VALUES (?, ?)
        ''', (password_id, encrypted_password))

    conn.commit()
    conn.close()

    return {"success": True}


@app.delete("/api/passwords/{password_id}")
def delete_password(password_id: int, session_id: str):
    """Delete a password."""
    get_session_cipher(session_id)  # Verify session

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM passwords WHERE id = ?', (password_id,))
    conn.commit()
    conn.close()

    return {"success": True}


@app.get("/api/categories")
def get_categories(session_id: str):
    """Get all categories."""
    get_session_cipher(session_id)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name FROM categories ORDER BY name')
    results = [{"id": row['id'], "name": row['name']} for row in cursor.fetchall()]
    conn.close()

    return {"categories": results}


@app.post("/api/categories")
def add_category(category: CategoryCreate, session_id: str):
    """Add a new category."""
    get_session_cipher(session_id)

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO categories (name) VALUES (?)', (category.name,))
        conn.commit()
        category_id = cursor.lastrowid
        conn.close()
        return {"success": True, "id": category_id}
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Category already exists")


@app.get("/api/passwords/{password_id}/history")
def get_password_history(password_id: int, session_id: str):
    """Get password history."""
    cipher = get_session_cipher(session_id)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT encrypted_password, changed_at
        FROM password_history
        WHERE password_id = ?
        ORDER BY changed_at DESC
    ''', (password_id,))

    history = []
    for row in cursor.fetchall():
        try:
            decrypted = cipher.decrypt(row['encrypted_password'].encode()).decode()
            history.append({"password": decrypted, "changed_at": row['changed_at']})
        except:
            pass

    conn.close()
    return {"history": history}


@app.get("/api/passwords/{password_id}/2fa")
def get_2fa_codes(password_id: int, session_id: str):
    """Get 2FA codes for a password."""
    cipher = get_session_cipher(session_id)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT encrypted_codes FROM two_factor_codes
        WHERE password_id = ?
        ORDER BY created_at DESC LIMIT 1
    ''', (password_id,))

    row = cursor.fetchone()
    conn.close()

    if row:
        try:
            codes = json.loads(cipher.decrypt(row['encrypted_codes'].encode()).decode())
            return {"codes": codes}
        except:
            pass

    return {"codes": []}




@app.post("/api/passwords/{password_id}/2fa")
def save_2fa_codes(password_id: int, codes: TwoFactorCodes, session_id: str):
    """Save 2FA codes for a password."""
    cipher = get_session_cipher(session_id)
    encrypted_codes = cipher.encrypt(json.dumps(codes.codes).encode()).decode()

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM two_factor_codes WHERE password_id = ?', (password_id,))
    cursor.execute('''
        INSERT INTO two_factor_codes (password_id, encrypted_codes)
        VALUES (?, ?)
    ''', (password_id, encrypted_codes))
    conn.commit()
    conn.close()

    return {"success": True}


@app.get("/api/settings")
def get_settings(session_id: str):
    """Get all settings."""
    get_session_cipher(session_id)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM config WHERE key IN ('theme', 'auto_lock_minutes', 'password_expiry_days')")
    settings = {row['key']: row['value'] for row in cursor.fetchall()}
    conn.close()

    return {"settings": settings}


@app.put("/api/settings")
def update_setting(setting: SettingUpdate, session_id: str):
    """Update a setting."""
    get_session_cipher(session_id)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('INSERT OR REPLACE INTO config VALUES (?, ?)', (setting.key, setting.value))
    conn.commit()
    conn.close()

    return {"success": True}


@app.get("/api/generate-password")
def generate_password(length: int = 16, include_special: bool = True):
    """Generate a random password."""
    chars = string.ascii_letters + string.digits
    if include_special:
        chars += "!@#$%^&*"

    password = ''.join(secrets.choice(chars) for _ in range(length))
    return {"password": password}


@app.get("/api/password-strength")
def check_password_strength(password: str):
    """Check password strength."""
    return calculate_password_strength(password)


# Serve frontend for all non-API routes
@app.get("/{full_path:path}")
def serve_frontend(full_path: str):
    """Serve the React frontend."""
    if os.path.exists(STATIC_DIR):
        file_path = os.path.join(STATIC_DIR, full_path)
        if os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))
    return {"error": "Frontend not built. Run 'npm run build' in frontend folder."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)