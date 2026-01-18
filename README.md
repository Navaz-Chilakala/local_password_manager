# 🔐 Local Password Manager

A secure, local password manager with a React frontend and Python FastAPI backend.

## Features

- 🔒 **AES Encryption** - All passwords encrypted with Fernet (AES-128)
- 🔑 **Master Password** - PBKDF2 key derivation with 100,000 iterations
- 📊 **Password Strength Meter** - Visual indicator when creating passwords
- ⏰ **Auto-Lock** - Automatically locks after inactivity
- 📁 **Categories** - Organize passwords (Social, Banking, Work, etc.)
- 🌙 **Dark Mode** - Toggle between light and dark themes
- 📜 **Password History** - Track previous passwords
- 🔢 **2FA Backup Codes** - Store two-factor authentication codes
- 🎲 **Password Generator** - Generate secure random passwords
- 🔍 **Search & Filter** - Find passwords quickly

## Tech Stack

| Component | Technology |
|-----------|------------|
| Frontend | React + Vite + TypeScript |
| Backend | Python + FastAPI |
| Database | SQLite (local) |
| Encryption | cryptography (Fernet/AES) |

## Quick Start

### Prerequisites

- Python 3.8+
- Node.js 16+
- npm

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd local_password_manager
   ```

2. **Install Python dependencies**
   ```bash
   pip install fastapi uvicorn cryptography
   ```

3. **Install frontend dependencies**
   ```bash
   cd frontend
   npm install
   cd ..
   ```

### Running the App

**Terminal 1 - Start Backend:**
```bash
cd backend
python -m uvicorn app:app --reload --port 8000
```

**Terminal 2 - Start Frontend:**
```bash
cd frontend
npm run dev
```

**Open browser:** http://localhost:5173

## Project Structure

```
local_password_manager/
├── backend/
│   ├── app.py          # FastAPI backend
│   └── passwords.db    # SQLite database (created on first run)
├── frontend/
│   ├── src/
│   │   ├── App.tsx     # Main React component
│   │   ├── App.css     # Styles
│   │   ├── api.ts      # API client
│   │   └── types.ts    # TypeScript types
│   └── package.json
├── main.py             # Tkinter version (standalone)
└── README.md
```

## Security

- All passwords are encrypted locally using AES-128 (Fernet)
- Master password is never stored - only a hash
- PBKDF2 with 100,000 iterations for key derivation
- Data never leaves your machine

## License

MIT

