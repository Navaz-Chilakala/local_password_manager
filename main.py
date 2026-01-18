#!/usr/bin/env python3
"""
Password Manager with GUI
A secure, encrypted password manager with a graphical interface.

INSTALLATION:
    pip install cryptography

FEATURES:
    - Master password protection with PBKDF2 key derivation
    - AES encryption for all stored passwords
    - Password strength meter
    - Auto-lock after inactivity
    - Export/Import encrypted backups
    - Password categories
    - Password expiry reminders
    - Dark/Light mode toggle
    - Copy username/password to clipboard
    - Service icons for common websites
    - Password history tracking
    - Two-factor backup codes storage
"""

import sqlite3
import secrets
import string
import hashlib
import base64
import os
import json
import re
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Default categories
DEFAULT_CATEGORIES = [
    "Social Media", "Banking", "Work", "Shopping",
    "Entertainment", "Email", "Gaming", "Other"
]

# Service icons (emoji-based for simplicity)
SERVICE_ICONS = {
    "google": "🔍", "gmail": "📧", "facebook": "📘", "twitter": "🐦",
    "instagram": "📷", "linkedin": "💼", "github": "🐙", "amazon": "📦",
    "netflix": "🎬", "spotify": "🎵", "apple": "🍎", "microsoft": "🪟",
    "paypal": "💳", "bank": "🏦", "steam": "🎮", "discord": "💬",
    "slack": "💬", "dropbox": "📁", "reddit": "🔴", "youtube": "▶️",
    "twitch": "🎮", "pinterest": "📌", "snapchat": "👻", "tiktok": "🎵",
    "zoom": "📹", "adobe": "🎨", "wordpress": "📝", "shopify": "🛒",
}


class PasswordManager:
    def __init__(self, db_path="passwords.db"):
        self.db_path = db_path
        self.cipher = None
        
    def _derive_key(self, master_password, salt):
        """Derive an encryption key from the master password."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key
    
    def _hash_master_password(self, master_password):
        """Hash the master password for verification."""
        return hashlib.sha256(master_password.encode()).hexdigest()
    
    def initialize_database(self, master_password):
        """Create a new password database."""
        salt = os.urandom(16)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            )
        ''')

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

        cursor.execute('INSERT INTO config VALUES (?, ?)',
                      ('salt', base64.b64encode(salt).decode()))
        cursor.execute('INSERT INTO config VALUES (?, ?)',
                      ('master_hash', self._hash_master_password(master_password)))
        cursor.execute('INSERT INTO config VALUES (?, ?)',
                      ('theme', 'light'))
        cursor.execute('INSERT INTO config VALUES (?, ?)',
                      ('auto_lock_minutes', '5'))
        cursor.execute('INSERT INTO config VALUES (?, ?)',
                      ('password_expiry_days', '90'))

        conn.commit()
        conn.close()
        
    def unlock(self, master_password):
        """Unlock the password manager."""
        if not os.path.exists(self.db_path):
            return False, "Database not found"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT value FROM config WHERE key = ?', ('salt',))
        result = cursor.fetchone()
        if not result:
            conn.close()
            return False, "Invalid database"
            
        salt = base64.b64decode(result[0])
        
        cursor.execute('SELECT value FROM config WHERE key = ?', ('master_hash',))
        stored_hash = cursor.fetchone()[0]
        conn.close()
        
        if self._hash_master_password(master_password) != stored_hash:
            return False, "Incorrect password"
        
        key = self._derive_key(master_password, salt)
        self.cipher = Fernet(key)
        
        return True, "Unlocked successfully"
    
    def add_password(self, service, username, password, notes="", category_id=None):
        """Add a new password entry."""
        if not self.cipher:
            return False, "Manager is locked"

        encrypted_password = self.cipher.encrypt(password.encode()).decode()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO passwords (service, username, encrypted_password, notes, category_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (service, username, encrypted_password, notes, category_id))

        password_id = cursor.lastrowid

        # Add to password history
        cursor.execute('''
            INSERT INTO password_history (password_id, encrypted_password)
            VALUES (?, ?)
        ''', (password_id, encrypted_password))

        conn.commit()
        conn.close()

        return True, "Password saved"
    
    def get_all_passwords(self):
        """Get all password entries."""
        if not self.cipher:
            return []

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT p.id, p.service, p.username, p.encrypted_password, p.notes,
                   p.created_at, p.updated_at, c.name as category, p.category_id
            FROM passwords p
            LEFT JOIN categories c ON p.category_id = c.id
            ORDER BY p.service
        ''')

        results = cursor.fetchall()
        conn.close()

        decrypted_entries = []
        for row in results:
            id, service, username, encrypted_password, notes, created_at, updated_at, category, category_id = row
            try:
                decrypted_password = self.cipher.decrypt(encrypted_password.encode()).decode()
                decrypted_entries.append({
                    'id': id,
                    'service': service,
                    'username': username,
                    'password': decrypted_password,
                    'notes': notes or '',
                    'created_at': created_at,
                    'updated_at': updated_at,
                    'category': category or 'Other',
                    'category_id': category_id
                })
            except:
                pass

        return decrypted_entries

    def get_categories(self):
        """Get all categories."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT id, name FROM categories ORDER BY name')
        results = cursor.fetchall()
        conn.close()
        return results

    def add_category(self, name):
        """Add a new category."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO categories (name) VALUES (?)', (name,))
            conn.commit()
            result = True, "Category added"
        except sqlite3.IntegrityError:
            result = False, "Category already exists"
        conn.close()
        return result
    
    def delete_password(self, password_id):
        """Delete a password entry."""
        if not self.cipher:
            return False, "Manager is locked"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM passwords WHERE id = ?', (password_id,))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        return success, "Password deleted" if success else "Password not found"
    
    def update_password(self, password_id, service, username, password, notes="", category_id=None):
        """Update an existing password entry."""
        if not self.cipher:
            return False, "Manager is locked"

        encrypted_password = self.cipher.encrypt(password.encode()).decode()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get current password to check if it changed
        cursor.execute('SELECT encrypted_password FROM passwords WHERE id = ?', (password_id,))
        old_row = cursor.fetchone()

        cursor.execute('''
            UPDATE passwords
            SET service = ?, username = ?, encrypted_password = ?, notes = ?,
                category_id = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (service, username, encrypted_password, notes, category_id, password_id))

        # Add to history if password changed
        if old_row and old_row[0] != encrypted_password:
            cursor.execute('''
                INSERT INTO password_history (password_id, encrypted_password)
                VALUES (?, ?)
            ''', (password_id, encrypted_password))

        success = cursor.rowcount > 0
        conn.commit()
        conn.close()

        return success, "Password updated" if success else "Password not found"

    def get_password_history(self, password_id):
        """Get password history for an entry."""
        if not self.cipher:
            return []

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT encrypted_password, changed_at
            FROM password_history
            WHERE password_id = ?
            ORDER BY changed_at DESC
        ''', (password_id,))

        results = cursor.fetchall()
        conn.close()

        history = []
        for encrypted_password, changed_at in results:
            try:
                decrypted = self.cipher.decrypt(encrypted_password.encode()).decode()
                history.append({'password': decrypted, 'changed_at': changed_at})
            except:
                pass

        return history
    
    # 2FA Codes Methods
    def save_2fa_codes(self, password_id, codes):
        """Save 2FA backup codes for a password entry."""
        if not self.cipher:
            return False, "Manager is locked"

        encrypted_codes = self.cipher.encrypt(json.dumps(codes).encode()).decode()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Delete existing codes and insert new ones
        cursor.execute('DELETE FROM two_factor_codes WHERE password_id = ?', (password_id,))
        cursor.execute('''
            INSERT INTO two_factor_codes (password_id, encrypted_codes)
            VALUES (?, ?)
        ''', (password_id, encrypted_codes))

        conn.commit()
        conn.close()
        return True, "2FA codes saved"

    def get_2fa_codes(self, password_id):
        """Get 2FA backup codes for a password entry."""
        if not self.cipher:
            return []

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT encrypted_codes FROM two_factor_codes
            WHERE password_id = ?
            ORDER BY created_at DESC LIMIT 1
        ''', (password_id,))

        result = cursor.fetchone()
        conn.close()

        if result:
            try:
                decrypted = self.cipher.decrypt(result[0].encode()).decode()
                return json.loads(decrypted)
            except:
                pass
        return []

    # Settings Methods
    def get_setting(self, key, default=None):
        """Get a setting value."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT value FROM config WHERE key = ?', (key,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else default

    def set_setting(self, key, value):
        """Set a setting value."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', (key, value))
        conn.commit()
        conn.close()

    # Export/Import Methods
    def export_passwords(self, filepath, export_password):
        """Export all passwords to an encrypted file."""
        if not self.cipher:
            return False, "Manager is locked"

        passwords = self.get_all_passwords()

        # Get 2FA codes for each password
        for pwd in passwords:
            pwd['two_factor_codes'] = self.get_2fa_codes(pwd['id'])

        # Create export cipher
        salt = os.urandom(16)
        export_key = self._derive_key(export_password, salt)
        export_cipher = Fernet(export_key)

        export_data = {
            'version': '2.0',
            'exported_at': datetime.now().isoformat(),
            'passwords': passwords
        }

        encrypted_data = export_cipher.encrypt(json.dumps(export_data).encode())

        with open(filepath, 'wb') as f:
            f.write(salt + encrypted_data)

        return True, f"Exported {len(passwords)} passwords"

    def import_passwords(self, filepath, import_password):
        """Import passwords from an encrypted file."""
        if not self.cipher:
            return False, "Manager is locked"

        try:
            with open(filepath, 'rb') as f:
                data = f.read()

            salt = data[:16]
            encrypted_data = data[16:]

            import_key = self._derive_key(import_password, salt)
            import_cipher = Fernet(import_key)

            decrypted = import_cipher.decrypt(encrypted_data)
            export_data = json.loads(decrypted.decode())

            imported_count = 0
            for pwd in export_data.get('passwords', []):
                self.add_password(
                    pwd['service'],
                    pwd['username'],
                    pwd['password'],
                    pwd.get('notes', ''),
                    pwd.get('category_id')
                )

                # Import 2FA codes if present
                if pwd.get('two_factor_codes'):
                    # Get the last inserted password id
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    cursor.execute('SELECT MAX(id) FROM passwords')
                    new_id = cursor.fetchone()[0]
                    conn.close()
                    self.save_2fa_codes(new_id, pwd['two_factor_codes'])

                imported_count += 1

            return True, f"Imported {imported_count} passwords"
        except Exception as e:
            return False, f"Import failed: {str(e)}"

    @staticmethod
    def calculate_password_strength(password):
        """Calculate password strength score (0-100)."""
        if not password:
            return 0, "Empty", "#dc3545"

        score = 0

        # Length scoring
        length = len(password)
        if length >= 8:
            score += 20
        if length >= 12:
            score += 15
        if length >= 16:
            score += 10
        if length >= 20:
            score += 5

        # Character diversity
        if re.search(r'[a-z]', password):
            score += 10
        if re.search(r'[A-Z]', password):
            score += 15
        if re.search(r'[0-9]', password):
            score += 15
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 20

        # Penalty for common patterns
        if re.search(r'(.)\1{2,}', password):  # Repeated characters
            score -= 10
        if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
            score -= 10
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi)', password.lower()):
            score -= 10

        score = max(0, min(100, score))

        if score < 30:
            return score, "Weak", "#dc3545"
        elif score < 50:
            return score, "Fair", "#fd7e14"
        elif score < 70:
            return score, "Good", "#ffc107"
        elif score < 90:
            return score, "Strong", "#28a745"
        else:
            return score, "Excellent", "#20c997"

    @staticmethod
    def generate_password(length=16, use_symbols=True):
        """Generate a secure random password."""
        characters = string.ascii_letters + string.digits
        if use_symbols:
            characters += string.punctuation

        password = ''.join(secrets.choice(characters) for _ in range(length))
        return password

    @staticmethod
    def get_service_icon(service):
        """Get icon for a service."""
        service_lower = service.lower()
        for key, icon in SERVICE_ICONS.items():
            if key in service_lower:
                return icon
        return "🔑"


class PasswordManagerGUI:
    # Theme configurations
    THEMES = {
        'light': {
            'bg': '#f5f5f5',
            'fg': '#333333',
            'entry_bg': '#ffffff',
            'button_bg': '#e0e0e0',
            'tree_bg': '#ffffff',
            'tree_fg': '#333333',
            'select_bg': '#0078d4',
            'accent': '#0078d4'
        },
        'dark': {
            'bg': '#1e1e1e',
            'fg': '#ffffff',
            'entry_bg': '#2d2d2d',
            'button_bg': '#3d3d3d',
            'tree_bg': '#252526',
            'tree_fg': '#cccccc',
            'select_bg': '#0078d4',
            'accent': '#0078d4'
        }
    }

    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Password Manager")
        self.root.geometry("1000x650")
        self.root.resizable(True, True)

        self.pm = PasswordManager()
        self.is_locked = True
        self.current_theme = 'light'
        self.auto_lock_timer = None
        self.last_activity = datetime.now()
        self.all_passwords = []
        self.current_category_filter = "All"

        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')

        # Check if database exists
        if not os.path.exists(self.pm.db_path):
            self.show_setup_screen()
        else:
            # Load theme preference
            self.current_theme = self.pm.get_setting('theme', 'light')
            self.show_login_screen()

    def apply_theme(self, theme_name=None):
        """Apply the specified theme."""
        if theme_name:
            self.current_theme = theme_name

        theme = self.THEMES[self.current_theme]

        self.root.configure(bg=theme['bg'])

        # Configure ttk styles
        self.style.configure('TFrame', background=theme['bg'])
        self.style.configure('TLabel', background=theme['bg'], foreground=theme['fg'])
        self.style.configure('TButton', background=theme['button_bg'], foreground=theme['fg'])
        self.style.configure('TEntry', fieldbackground=theme['entry_bg'], foreground=theme['fg'])
        self.style.configure('TCheckbutton', background=theme['bg'], foreground=theme['fg'])
        self.style.configure('TCombobox', fieldbackground=theme['entry_bg'], foreground=theme['fg'])
        self.style.configure('Treeview',
                            background=theme['tree_bg'],
                            foreground=theme['tree_fg'],
                            fieldbackground=theme['tree_bg'])
        self.style.configure('Treeview.Heading',
                            background=theme['button_bg'],
                            foreground=theme['fg'])
        self.style.map('Treeview',
                      background=[('selected', theme['select_bg'])],
                      foreground=[('selected', '#ffffff')])

        # Save preference
        if not self.is_locked:
            self.pm.set_setting('theme', self.current_theme)

    def toggle_theme(self):
        """Toggle between light and dark themes."""
        new_theme = 'dark' if self.current_theme == 'light' else 'light'
        self.apply_theme(new_theme)
        self.show_main_screen()  # Refresh to apply theme

    def reset_activity_timer(self, event=None):
        """Reset the auto-lock timer on user activity."""
        self.last_activity = datetime.now()

    def start_auto_lock_timer(self):
        """Start the auto-lock timer."""
        if self.auto_lock_timer:
            self.root.after_cancel(self.auto_lock_timer)

        # Bind activity events
        self.root.bind('<Motion>', self.reset_activity_timer)
        self.root.bind('<KeyPress>', self.reset_activity_timer)
        self.root.bind('<Button>', self.reset_activity_timer)

        self.check_auto_lock()

    def check_auto_lock(self):
        """Check if auto-lock should trigger."""
        if self.is_locked:
            return

        auto_lock_minutes = int(self.pm.get_setting('auto_lock_minutes', '5'))
        if auto_lock_minutes <= 0:
            self.auto_lock_timer = self.root.after(60000, self.check_auto_lock)
            return

        elapsed = (datetime.now() - self.last_activity).total_seconds() / 60

        if elapsed >= auto_lock_minutes:
            self.lock_manager()
            messagebox.showinfo("Auto-Locked", "Password manager locked due to inactivity")
        else:
            # Check again in 30 seconds
            self.auto_lock_timer = self.root.after(30000, self.check_auto_lock)

    def stop_auto_lock_timer(self):
        """Stop the auto-lock timer."""
        if self.auto_lock_timer:
            self.root.after_cancel(self.auto_lock_timer)
            self.auto_lock_timer = None
    
    def show_setup_screen(self):
        """Show initial setup screen."""
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="40")
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ttk.Label(frame, text="Welcome to Password Manager", 
                 font=("Arial", 20, "bold")).pack(pady=20)
        
        ttk.Label(frame, text="Create a master password to secure your passwords",
                 font=("Arial", 11)).pack(pady=10)
        
        ttk.Label(frame, text="Master Password:").pack(pady=(20, 5))
        password_entry = ttk.Entry(frame, show="*", width=30)
        password_entry.pack(pady=5)
        
        ttk.Label(frame, text="Confirm Password:").pack(pady=(10, 5))
        confirm_entry = ttk.Entry(frame, show="*", width=30)
        confirm_entry.pack(pady=5)
        
        def setup():
            password = password_entry.get()
            confirm = confirm_entry.get()
            
            if not password:
                messagebox.showerror("Error", "Please enter a password")
                return
            
            if password != confirm:
                messagebox.showerror("Error", "Passwords don't match")
                return
            
            if len(password) < 6:
                messagebox.showerror("Error", "Password must be at least 6 characters")
                return
            
            self.pm.initialize_database(password)
            success, msg = self.pm.unlock(password)
            
            if success:
                self.is_locked = False
                messagebox.showinfo("Success", "Password manager created successfully!")
                self.show_main_screen()
            else:
                messagebox.showerror("Error", msg)
        
        ttk.Button(frame, text="Create Password Manager", 
                  command=setup, width=25).pack(pady=20)
        
        password_entry.focus()
        confirm_entry.bind('<Return>', lambda e: setup())
    
    def show_login_screen(self):
        """Show login screen."""
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="40")
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ttk.Label(frame, text="Password Manager", 
                 font=("Arial", 20, "bold")).pack(pady=20)
        
        ttk.Label(frame, text="Enter your master password to unlock",
                 font=("Arial", 11)).pack(pady=10)
        
        ttk.Label(frame, text="Master Password:").pack(pady=(20, 5))
        password_entry = ttk.Entry(frame, show="*", width=30)
        password_entry.pack(pady=5)
        
        def login():
            password = password_entry.get()
            
            if not password:
                messagebox.showerror("Error", "Please enter your password")
                return
            
            success, msg = self.pm.unlock(password)
            
            if success:
                self.is_locked = False
                self.show_main_screen()
            else:
                messagebox.showerror("Error", msg)
                password_entry.delete(0, tk.END)
        
        ttk.Button(frame, text="Unlock", command=login, width=20).pack(pady=20)
        
        password_entry.focus()
        password_entry.bind('<Return>', lambda e: login())
    
    def show_main_screen(self):
        """Show main password management screen."""
        self.clear_window()
        self.apply_theme()
        self.start_auto_lock_timer()
        self.reset_activity_timer()

        # Check for expiring passwords
        self.check_expiring_passwords()

        # Top toolbar
        toolbar = ttk.Frame(self.root)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

        ttk.Label(toolbar, text="🔐 Password Manager",
                 font=("Arial", 16, "bold")).pack(side=tk.LEFT, padx=10)

        # Right side buttons
        ttk.Button(toolbar, text="➕ Add",
                  command=self.show_add_dialog).pack(side=tk.RIGHT, padx=3)

        ttk.Button(toolbar, text="🔄 Refresh",
                  command=self.refresh_list).pack(side=tk.RIGHT, padx=3)

        ttk.Button(toolbar, text="🔒 Lock",
                  command=self.lock_manager).pack(side=tk.RIGHT, padx=3)

        theme_icon = "🌙" if self.current_theme == 'light' else "☀️"
        ttk.Button(toolbar, text=f"{theme_icon} Theme",
                  command=self.toggle_theme).pack(side=tk.RIGHT, padx=3)

        ttk.Button(toolbar, text="⚙️ Settings",
                  command=self.show_settings_dialog).pack(side=tk.RIGHT, padx=3)

        ttk.Button(toolbar, text="📤 Export",
                  command=self.export_passwords).pack(side=tk.RIGHT, padx=3)

        ttk.Button(toolbar, text="📥 Import",
                  command=self.import_passwords).pack(side=tk.RIGHT, padx=3)

        # Search and filter bar
        search_frame = ttk.Frame(self.root)
        search_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=(0, 10))

        ttk.Label(search_frame, text="🔍 Search:").pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        self.search_var.trace('w', lambda *args: self.filter_list())
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)

        # Category filter
        ttk.Label(search_frame, text="📁 Category:").pack(side=tk.LEFT, padx=(20, 5))
        self.category_var = tk.StringVar(value="All")
        categories = ["All"] + [cat[1] for cat in self.pm.get_categories()]
        category_combo = ttk.Combobox(search_frame, textvariable=self.category_var,
                                      values=categories, state="readonly", width=15)
        category_combo.pack(side=tk.LEFT, padx=5)
        category_combo.bind('<<ComboboxSelected>>', lambda e: self.filter_list())

        # Password list with scrollbar
        list_frame = ttk.Frame(self.root)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # Treeview with new columns
        columns = ('Icon', 'Service', 'Username', 'Password', 'Category', 'Age', 'Notes')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='tree headings', height=18)

        self.tree.heading('#0', text='')
        self.tree.heading('Icon', text='')
        self.tree.heading('Service', text='Service')
        self.tree.heading('Username', text='Username')
        self.tree.heading('Password', text='Password')
        self.tree.heading('Category', text='Category')
        self.tree.heading('Age', text='Age')
        self.tree.heading('Notes', text='Notes')

        self.tree.column('#0', width=0, stretch=False)
        self.tree.column('Icon', width=40, anchor='center')
        self.tree.column('Service', width=140)
        self.tree.column('Username', width=140)
        self.tree.column('Password', width=120)
        self.tree.column('Category', width=100)
        self.tree.column('Age', width=80)
        self.tree.column('Notes', width=180)

        # Scrollbars
        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        hsb = ttk.Scrollbar(list_frame, orient="horizontal", command=self.tree.xview)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Context menu
        self.tree.bind('<Button-3>', self.show_context_menu)
        self.tree.bind('<Double-1>', self.view_password)

        # Bottom status bar
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.refresh_list()
    
    def calculate_age(self, date_str):
        """Calculate age of password in days."""
        try:
            if isinstance(date_str, str):
                created = datetime.strptime(date_str.split('.')[0], '%Y-%m-%d %H:%M:%S')
            else:
                created = date_str
            days = (datetime.now() - created).days
            if days == 0:
                return "Today"
            elif days == 1:
                return "1 day"
            elif days < 30:
                return f"{days} days"
            elif days < 365:
                months = days // 30
                return f"{months} mo"
            else:
                years = days // 365
                return f"{years} yr"
        except:
            return "Unknown"

    def refresh_list(self):
        """Refresh the password list."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        passwords = self.pm.get_all_passwords()
        self.all_passwords = passwords

        for pwd in passwords:
            icon = PasswordManager.get_service_icon(pwd['service'])
            masked_password = '•' * min(len(pwd['password']), 12)
            age = self.calculate_age(pwd.get('updated_at') or pwd['created_at'])
            notes_preview = pwd['notes'][:25] + '...' if len(pwd['notes']) > 25 else pwd['notes']

            self.tree.insert('', tk.END, text=pwd['id'], values=(
                icon,
                pwd['service'],
                pwd['username'],
                masked_password,
                pwd.get('category', 'Other'),
                age,
                notes_preview
            ))

        self.status_bar.config(text=f"Total passwords: {len(passwords)}")

    def filter_list(self):
        """Filter password list based on search and category."""
        search_term = self.search_var.get().lower()
        category_filter = self.category_var.get() if hasattr(self, 'category_var') else "All"

        for item in self.tree.get_children():
            self.tree.delete(item)

        filtered_count = 0
        for pwd in self.all_passwords:
            # Check search term
            matches_search = (search_term in pwd['service'].lower() or
                             search_term in pwd['username'].lower() or
                             search_term in pwd['notes'].lower())

            # Check category
            matches_category = (category_filter == "All" or
                              pwd.get('category', 'Other') == category_filter)

            if matches_search and matches_category:
                icon = PasswordManager.get_service_icon(pwd['service'])
                masked_password = '•' * min(len(pwd['password']), 12)
                age = self.calculate_age(pwd.get('updated_at') or pwd['created_at'])
                notes_preview = pwd['notes'][:25] + '...' if len(pwd['notes']) > 25 else pwd['notes']

                self.tree.insert('', tk.END, text=pwd['id'], values=(
                    icon,
                    pwd['service'],
                    pwd['username'],
                    masked_password,
                    pwd.get('category', 'Other'),
                    age,
                    notes_preview
                ))
                filtered_count += 1

        self.status_bar.config(text=f"Showing {filtered_count} of {len(self.all_passwords)} passwords")

    def check_expiring_passwords(self):
        """Check for passwords that are expiring soon."""
        expiry_days = int(self.pm.get_setting('password_expiry_days', '90'))
        if expiry_days <= 0:
            return

        expiring = []
        for pwd in self.pm.get_all_passwords():
            try:
                date_str = pwd.get('updated_at') or pwd['created_at']
                if isinstance(date_str, str):
                    updated = datetime.strptime(date_str.split('.')[0], '%Y-%m-%d %H:%M:%S')
                else:
                    updated = date_str
                age_days = (datetime.now() - updated).days
                if age_days >= expiry_days:
                    expiring.append(pwd['service'])
            except:
                pass

        if expiring:
            services = ', '.join(expiring[:5])
            if len(expiring) > 5:
                services += f" and {len(expiring) - 5} more"
            messagebox.showwarning(
                "Password Expiry Warning",
                f"The following passwords are older than {expiry_days} days and should be updated:\n\n{services}"
            )
    
    def show_add_dialog(self):
        """Show dialog to add new password."""
        dialog = tk.Toplevel(self.root)
        dialog.title("➕ Add Password")
        dialog.geometry("450x550")
        dialog.transient(self.root)
        dialog.grab_set()

        # Create canvas with scrollbar for long content
        canvas = tk.Canvas(dialog)
        scrollbar = ttk.Scrollbar(dialog, orient="vertical", command=canvas.yview)
        frame = ttk.Frame(canvas, padding="20")

        frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Service name
        ttk.Label(frame, text="Service Name:").pack(anchor='w', pady=(0, 5))
        service_entry = ttk.Entry(frame, width=45)
        service_entry.pack(fill='x', pady=(0, 10))

        # Username
        ttk.Label(frame, text="Username / Email:").pack(anchor='w', pady=(0, 5))
        username_entry = ttk.Entry(frame, width=45)
        username_entry.pack(fill='x', pady=(0, 10))

        # Category
        ttk.Label(frame, text="Category:").pack(anchor='w', pady=(0, 5))
        categories = self.pm.get_categories()
        category_var = tk.StringVar()
        category_combo = ttk.Combobox(frame, textvariable=category_var,
                                      values=[c[1] for c in categories], width=42)
        category_combo.pack(fill='x', pady=(0, 10))
        if categories:
            category_combo.set(categories[0][1])

        # Password
        ttk.Label(frame, text="Password:").pack(anchor='w', pady=(0, 5))

        pwd_frame = ttk.Frame(frame)
        pwd_frame.pack(fill='x', pady=(0, 5))

        password_entry = ttk.Entry(pwd_frame, width=35, show="*")
        password_entry.pack(side=tk.LEFT, padx=(0, 5))

        show_var = tk.BooleanVar()
        def toggle_password():
            password_entry.config(show="" if show_var.get() else "*")

        ttk.Checkbutton(pwd_frame, text="👁", variable=show_var,
                       command=toggle_password, width=3).pack(side=tk.LEFT)

        # Password strength meter
        strength_frame = ttk.Frame(frame)
        strength_frame.pack(fill='x', pady=(5, 10))

        strength_bar = tk.Canvas(strength_frame, height=8, bg='#e0e0e0', highlightthickness=0)
        strength_bar.pack(fill='x', side=tk.LEFT, expand=True, padx=(0, 10))

        strength_label = ttk.Label(strength_frame, text="", width=10)
        strength_label.pack(side=tk.RIGHT)

        def update_strength(*args):
            pwd = password_entry.get()
            score, label, color = PasswordManager.calculate_password_strength(pwd)
            strength_bar.delete("all")
            if score > 0:
                width = strength_bar.winfo_width() * (score / 100)
                strength_bar.create_rectangle(0, 0, width, 10, fill=color, outline='')
            strength_label.config(text=label, foreground=color)

        password_entry.bind('<KeyRelease>', update_strength)

        # Generate password buttons
        gen_frame = ttk.Frame(frame)
        gen_frame.pack(fill='x', pady=(0, 10))

        def generate(length=16, symbols=True):
            pwd = PasswordManager.generate_password(length, symbols)
            password_entry.delete(0, tk.END)
            password_entry.insert(0, pwd)
            update_strength()

        ttk.Button(gen_frame, text="🎲 Generate (16)",
                  command=lambda: generate(16)).pack(side=tk.LEFT, padx=2)
        ttk.Button(gen_frame, text="🎲 Long (24)",
                  command=lambda: generate(24)).pack(side=tk.LEFT, padx=2)
        ttk.Button(gen_frame, text="🎲 Simple",
                  command=lambda: generate(12, False)).pack(side=tk.LEFT, padx=2)

        # Notes
        ttk.Label(frame, text="Notes (optional):").pack(anchor='w', pady=(0, 5))
        notes_text = tk.Text(frame, width=45, height=3)
        notes_text.pack(fill='x', pady=(0, 10))

        # 2FA Backup Codes
        ttk.Label(frame, text="2FA Backup Codes (optional, one per line):").pack(anchor='w', pady=(0, 5))
        codes_text = tk.Text(frame, width=45, height=3)
        codes_text.pack(fill='x', pady=(0, 15))

        def save():
            service = service_entry.get().strip()
            username = username_entry.get().strip()
            password = password_entry.get()
            notes = notes_text.get('1.0', tk.END).strip()
            codes = [c.strip() for c in codes_text.get('1.0', tk.END).strip().split('\n') if c.strip()]

            # Get category ID
            cat_name = category_var.get()
            category_id = None
            for c in categories:
                if c[1] == cat_name:
                    category_id = c[0]
                    break

            if not service or not username or not password:
                messagebox.showerror("Error", "Please fill all required fields")
                return

            success, msg = self.pm.add_password(service, username, password, notes, category_id)

            if success:
                # Save 2FA codes if provided
                if codes:
                    # Get the new password ID
                    passwords = self.pm.get_all_passwords()
                    if passwords:
                        new_pwd = max(passwords, key=lambda x: x['id'])
                        self.pm.save_2fa_codes(new_pwd['id'], codes)

                messagebox.showinfo("Success", msg)
                self.refresh_list()
                dialog.destroy()
            else:
                messagebox.showerror("Error", msg)

        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=15)

        ttk.Button(button_frame, text="💾 Save", command=save, width=12).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="❌ Cancel", command=dialog.destroy, width=12).pack(side=tk.LEFT, padx=5)

        service_entry.focus()
    
    def show_context_menu(self, event):
        """Show context menu on right-click."""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)

            menu = tk.Menu(self.root, tearoff=0)
            menu.add_command(label="👁 View Details", command=self.view_password)
            menu.add_separator()
            menu.add_command(label="📋 Copy Password", command=self.copy_password)
            menu.add_command(label="👤 Copy Username", command=self.copy_username)
            menu.add_separator()
            menu.add_command(label="📜 View History", command=self.view_password_history)
            menu.add_command(label="🔑 View 2FA Codes", command=self.view_2fa_codes)
            menu.add_separator()
            menu.add_command(label="✏️ Edit", command=self.edit_password)
            menu.add_command(label="🗑️ Delete", command=self.delete_password)

            menu.post(event.x_root, event.y_root)
    
    def view_password(self, event=None):
        """View password details."""
        selection = self.tree.selection()
        if not selection:
            return
        
        item = selection[0]
        pwd_id = int(self.tree.item(item, 'text'))
        
        # Find password in list
        pwd_data = next((p for p in self.all_passwords if p['id'] == pwd_id), None)
        
        if not pwd_data:
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Password Details - {pwd_data['service']}")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        
        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text=f"Service: {pwd_data['service']}", 
                 font=("Arial", 12, "bold")).pack(pady=10)
        
        ttk.Label(frame, text=f"Username: {pwd_data['username']}").pack(pady=5)
        
        pwd_frame = ttk.Frame(frame)
        pwd_frame.pack(pady=10)
        
        ttk.Label(pwd_frame, text="Password: ").pack(side=tk.LEFT)
        pwd_label = ttk.Label(pwd_frame, text=pwd_data['password'], 
                             font=("Courier", 10))
        pwd_label.pack(side=tk.LEFT)
        
        if pwd_data['notes']:
            ttk.Label(frame, text=f"Notes:").pack(pady=(15, 5))
            notes_frame = ttk.Frame(frame)
            notes_frame.pack(fill=tk.BOTH, expand=True)
            
            notes_text = tk.Text(notes_frame, height=5, width=40, wrap=tk.WORD)
            notes_text.insert('1.0', pwd_data['notes'])
            notes_text.config(state=tk.DISABLED)
            notes_text.pack()
        
        ttk.Label(frame, text=f"Created: {pwd_data['created_at']}").pack(pady=(15, 5))
        
        def copy():
            self.root.clipboard_clear()
            self.root.clipboard_append(pwd_data['password'])
            messagebox.showinfo("Success", "Password copied to clipboard!")
        
        ttk.Button(frame, text="Copy Password", command=copy).pack(pady=10)
    
    def copy_password(self):
        """Copy password to clipboard."""
        selection = self.tree.selection()
        if not selection:
            return
        
        item = selection[0]
        pwd_id = int(self.tree.item(item, 'text'))
        pwd_data = next((p for p in self.all_passwords if p['id'] == pwd_id), None)
        
        if pwd_data:
            self.root.clipboard_clear()
            self.root.clipboard_append(pwd_data['password'])
            self.status_bar.config(text=f"Password copied for {pwd_data['service']}")
    
    def copy_username(self):
        """Copy username to clipboard."""
        selection = self.tree.selection()
        if not selection:
            return

        item = selection[0]
        pwd_id = int(self.tree.item(item, 'text'))
        pwd_data = next((p for p in self.all_passwords if p['id'] == pwd_id), None)

        if pwd_data:
            self.root.clipboard_clear()
            self.root.clipboard_append(pwd_data['username'])
            self.status_bar.config(text=f"Username copied for {pwd_data['service']}")

    def view_password_history(self):
        """View password history for selected entry."""
        selection = self.tree.selection()
        if not selection:
            return

        item = selection[0]
        pwd_id = int(self.tree.item(item, 'text'))
        pwd_data = next((p for p in self.all_passwords if p['id'] == pwd_id), None)

        if not pwd_data:
            return

        history = self.pm.get_password_history(pwd_id)

        dialog = tk.Toplevel(self.root)
        dialog.title(f"📜 Password History - {pwd_data['service']}")
        dialog.geometry("400x300")
        dialog.transient(self.root)

        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        if not history:
            ttk.Label(frame, text="No password history available").pack(pady=20)
        else:
            ttk.Label(frame, text=f"Password history for {pwd_data['service']}:",
                     font=("Arial", 11, "bold")).pack(pady=(0, 10))

            tree = ttk.Treeview(frame, columns=('Password', 'Changed'), show='headings', height=8)
            tree.heading('Password', text='Password')
            tree.heading('Changed', text='Changed At')
            tree.column('Password', width=180)
            tree.column('Changed', width=150)

            for h in history:
                tree.insert('', tk.END, values=(h['password'], h['changed_at']))

            tree.pack(fill=tk.BOTH, expand=True)

        ttk.Button(frame, text="Close", command=dialog.destroy).pack(pady=10)

    def view_2fa_codes(self):
        """View 2FA backup codes for selected entry."""
        selection = self.tree.selection()
        if not selection:
            return

        item = selection[0]
        pwd_id = int(self.tree.item(item, 'text'))
        pwd_data = next((p for p in self.all_passwords if p['id'] == pwd_id), None)

        if not pwd_data:
            return

        codes = self.pm.get_2fa_codes(pwd_id)

        dialog = tk.Toplevel(self.root)
        dialog.title(f"🔑 2FA Codes - {pwd_data['service']}")
        dialog.geometry("350x300")
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="2FA Backup Codes:", font=("Arial", 11, "bold")).pack(pady=(0, 10))

        codes_text = tk.Text(frame, width=35, height=8)
        codes_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        if codes:
            codes_text.insert('1.0', '\n'.join(codes))
        else:
            codes_text.insert('1.0', 'No 2FA codes saved for this entry.')

        def save_codes():
            new_codes = [c.strip() for c in codes_text.get('1.0', tk.END).strip().split('\n') if c.strip()]
            self.pm.save_2fa_codes(pwd_id, new_codes)
            messagebox.showinfo("Success", "2FA codes saved")
            dialog.destroy()

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="💾 Save", command=save_codes).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="❌ Close", command=dialog.destroy).pack(side=tk.LEFT, padx=5)

    def edit_password(self):
        """Edit selected password."""
        selection = self.tree.selection()
        if not selection:
            return

        item = selection[0]
        pwd_id = int(self.tree.item(item, 'text'))
        pwd_data = next((p for p in self.all_passwords if p['id'] == pwd_id), None)

        if not pwd_data:
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("✏️ Edit Password")
        dialog.geometry("400x480")
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Service Name:").pack(anchor='w', pady=(0, 5))
        service_entry = ttk.Entry(frame, width=40)
        service_entry.insert(0, pwd_data['service'])
        service_entry.pack(fill='x', pady=(0, 10))

        ttk.Label(frame, text="Username:").pack(anchor='w', pady=(0, 5))
        username_entry = ttk.Entry(frame, width=40)
        username_entry.insert(0, pwd_data['username'])
        username_entry.pack(fill='x', pady=(0, 10))

        # Category
        ttk.Label(frame, text="Category:").pack(anchor='w', pady=(0, 5))
        categories = self.pm.get_categories()
        category_var = tk.StringVar(value=pwd_data.get('category', 'Other'))
        category_combo = ttk.Combobox(frame, textvariable=category_var,
                                      values=[c[1] for c in categories], width=37)
        category_combo.pack(fill='x', pady=(0, 10))

        ttk.Label(frame, text="Password:").pack(anchor='w', pady=(0, 5))

        pwd_frame = ttk.Frame(frame)
        pwd_frame.pack(fill='x', pady=(0, 5))

        password_entry = ttk.Entry(pwd_frame, width=30, show="*")
        password_entry.insert(0, pwd_data['password'])
        password_entry.pack(side=tk.LEFT, padx=(0, 5))

        show_var = tk.BooleanVar()
        def toggle_password():
            password_entry.config(show="" if show_var.get() else "*")

        ttk.Checkbutton(pwd_frame, text="👁", variable=show_var,
                       command=toggle_password).pack(side=tk.LEFT)

        ttk.Label(frame, text="Notes (optional):").pack(anchor='w', pady=(15, 5))
        notes_text = tk.Text(frame, width=40, height=4)
        notes_text.insert('1.0', pwd_data['notes'])
        notes_text.pack(fill='x', pady=(0, 15))

        def save():
            service = service_entry.get().strip()
            username = username_entry.get().strip()
            password = password_entry.get()
            notes = notes_text.get('1.0', tk.END).strip()

            # Get category ID
            cat_name = category_var.get()
            category_id = None
            for c in categories:
                if c[1] == cat_name:
                    category_id = c[0]
                    break

            if not service or not username or not password:
                messagebox.showerror("Error", "Please fill all required fields")
                return

            success, msg = self.pm.update_password(pwd_id, service, username, password, notes, category_id)

            if success:
                messagebox.showinfo("Success", msg)
                self.refresh_list()
                dialog.destroy()
            else:
                messagebox.showerror("Error", msg)

        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="💾 Save", command=save).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="❌ Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def delete_password(self):
        """Delete selected password."""
        selection = self.tree.selection()
        if not selection:
            return
        
        item = selection[0]
        values = self.tree.item(item, 'values')
        service = values[0]
        
        if messagebox.askyesno("Confirm Delete", 
                              f"Delete password for {service}?"):
            pwd_id = int(self.tree.item(item, 'text'))
            success, msg = self.pm.delete_password(pwd_id)
            
            if success:
                self.refresh_list()
                self.status_bar.config(text=msg)
            else:
                messagebox.showerror("Error", msg)
    
    def export_passwords(self):
        """Export passwords to encrypted file."""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".pwbak",
            filetypes=[("Password Backup", "*.pwbak"), ("All Files", "*.*")],
            title="Export Passwords"
        )

        if not filepath:
            return

        password = simpledialog.askstring(
            "Export Password",
            "Enter a password to encrypt the backup:",
            show='*'
        )

        if not password:
            return

        confirm = simpledialog.askstring(
            "Confirm Password",
            "Confirm the backup password:",
            show='*'
        )

        if password != confirm:
            messagebox.showerror("Error", "Passwords don't match")
            return

        success, msg = self.pm.export_passwords(filepath, password)

        if success:
            messagebox.showinfo("Export Complete", msg)
        else:
            messagebox.showerror("Export Failed", msg)

    def import_passwords(self):
        """Import passwords from encrypted file."""
        filepath = filedialog.askopenfilename(
            filetypes=[("Password Backup", "*.pwbak"), ("All Files", "*.*")],
            title="Import Passwords"
        )

        if not filepath:
            return

        password = simpledialog.askstring(
            "Import Password",
            "Enter the backup password:",
            show='*'
        )

        if not password:
            return

        success, msg = self.pm.import_passwords(filepath, password)

        if success:
            messagebox.showinfo("Import Complete", msg)
            self.refresh_list()
        else:
            messagebox.showerror("Import Failed", msg)

    def show_settings_dialog(self):
        """Show settings dialog."""
        dialog = tk.Toplevel(self.root)
        dialog.title("⚙️ Settings")
        dialog.geometry("400x400")
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Settings", font=("Arial", 14, "bold")).pack(pady=(0, 20))

        # Auto-lock timeout
        lock_frame = ttk.Frame(frame)
        lock_frame.pack(fill='x', pady=10)

        ttk.Label(lock_frame, text="Auto-lock after (minutes):").pack(side=tk.LEFT)
        lock_var = tk.StringVar(value=self.pm.get_setting('auto_lock_minutes', '5'))
        lock_spin = ttk.Spinbox(lock_frame, from_=0, to=60, width=5, textvariable=lock_var)
        lock_spin.pack(side=tk.RIGHT)
        ttk.Label(lock_frame, text="(0 = disabled)").pack(side=tk.RIGHT, padx=10)

        # Password expiry
        expiry_frame = ttk.Frame(frame)
        expiry_frame.pack(fill='x', pady=10)

        ttk.Label(expiry_frame, text="Password expiry warning (days):").pack(side=tk.LEFT)
        expiry_var = tk.StringVar(value=self.pm.get_setting('password_expiry_days', '90'))
        expiry_spin = ttk.Spinbox(expiry_frame, from_=0, to=365, width=5, textvariable=expiry_var)
        expiry_spin.pack(side=tk.RIGHT)
        ttk.Label(expiry_frame, text="(0 = disabled)").pack(side=tk.RIGHT, padx=10)

        # Theme
        theme_frame = ttk.Frame(frame)
        theme_frame.pack(fill='x', pady=10)

        ttk.Label(theme_frame, text="Theme:").pack(side=tk.LEFT)
        theme_var = tk.StringVar(value=self.current_theme)
        theme_combo = ttk.Combobox(theme_frame, textvariable=theme_var,
                                   values=['light', 'dark'], state='readonly', width=10)
        theme_combo.pack(side=tk.RIGHT)

        # Manage categories
        ttk.Label(frame, text="Categories:", font=("Arial", 11)).pack(anchor='w', pady=(20, 5))

        cat_frame = ttk.Frame(frame)
        cat_frame.pack(fill='x', pady=5)

        categories = self.pm.get_categories()
        cat_listbox = tk.Listbox(cat_frame, height=6)
        for cat in categories:
            cat_listbox.insert(tk.END, cat[1])
        cat_listbox.pack(side=tk.LEFT, fill='x', expand=True)

        cat_btn_frame = ttk.Frame(cat_frame)
        cat_btn_frame.pack(side=tk.RIGHT, padx=10)

        new_cat_entry = ttk.Entry(frame, width=30)
        new_cat_entry.pack(pady=5)

        def add_category():
            name = new_cat_entry.get().strip()
            if name:
                success, msg = self.pm.add_category(name)
                if success:
                    cat_listbox.insert(tk.END, name)
                    new_cat_entry.delete(0, tk.END)
                else:
                    messagebox.showerror("Error", msg)

        ttk.Button(frame, text="➕ Add Category", command=add_category).pack(pady=5)

        def save_settings():
            self.pm.set_setting('auto_lock_minutes', lock_var.get())
            self.pm.set_setting('password_expiry_days', expiry_var.get())

            if theme_var.get() != self.current_theme:
                self.apply_theme(theme_var.get())

            messagebox.showinfo("Success", "Settings saved")
            dialog.destroy()
            self.show_main_screen()  # Refresh

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)

        ttk.Button(btn_frame, text="💾 Save", command=save_settings).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="❌ Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)

    def lock_manager(self):
        """Lock the password manager."""
        self.stop_auto_lock_timer()
        self.is_locked = True
        self.pm.cipher = None
        self.show_login_screen()

    def clear_window(self):
        """Clear all widgets from window."""
        for widget in self.root.winfo_children():
            widget.destroy()


def main():
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()