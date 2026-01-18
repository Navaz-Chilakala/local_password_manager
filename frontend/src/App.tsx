import { useState, useEffect, useCallback } from 'react';
import { api, getSession, setSession } from './api';
import type { PasswordEntry, Category } from './types';
import './App.css';

type Screen = 'loading' | 'setup' | 'login' | 'main' | 'error';

function App() {
  const [screen, setScreen] = useState<Screen>('loading');
  const [theme, setTheme] = useState<'light' | 'dark'>('light');
  const [passwords, setPasswords] = useState<PasswordEntry[]>([]);
  const [categories, setCategories] = useState<Category[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('All');
  const [error, setError] = useState('');
  const [lastActivity, setLastActivity] = useState(Date.now());
  const [autoLockMinutes, setAutoLockMinutes] = useState(5);
  const [connectionError, setConnectionError] = useState('');

  // Check status on load
  useEffect(() => {
    checkStatus();
  }, []);

  // Auto-lock timer
  useEffect(() => {
    if (screen !== 'main' || autoLockMinutes === 0) return;

    const interval = setInterval(() => {
      if (Date.now() - lastActivity > autoLockMinutes * 60 * 1000) {
        handleLogout();
      }
    }, 10000);

    return () => clearInterval(interval);
  }, [screen, lastActivity, autoLockMinutes]);

  // Activity tracking
  const resetActivity = useCallback(() => setLastActivity(Date.now()), []);

  useEffect(() => {
    window.addEventListener('mousemove', resetActivity);
    window.addEventListener('keydown', resetActivity);
    return () => {
      window.removeEventListener('mousemove', resetActivity);
      window.removeEventListener('keydown', resetActivity);
    };
  }, [resetActivity]);

  // Theme
  useEffect(() => {
    document.body.className = theme;
  }, [theme]);

  const checkStatus = async () => {
    try {
      const status = await api.getStatus();
      if (!status.initialized) {
        setScreen('setup');
      } else if (getSession()) {
        await loadData();
        setScreen('main');
      } else {
        setScreen('login');
      }
    } catch (err) {
      console.error('API Error:', err);
      setConnectionError('Cannot connect to backend. Make sure the Python server is running on port 8000.');
      setScreen('error');
    }
  };

  const loadData = async () => {
    try {
      const [pwdRes, catRes, settingsRes] = await Promise.all([
        api.getPasswords(),
        api.getCategories(),
        api.getSettings()
      ]);
      setPasswords(pwdRes.passwords);
      setCategories(catRes.categories);
      if (settingsRes.settings.theme) setTheme(settingsRes.settings.theme as 'light' | 'dark');
      if (settingsRes.settings.auto_lock_minutes) setAutoLockMinutes(parseInt(settingsRes.settings.auto_lock_minutes));
    } catch {
      handleLogout();
    }
  };

  const handleLogout = () => {
    api.logout().catch(() => {});
    setSession(null);
    setScreen('login');
    setPasswords([]);
  };

  const filteredPasswords = passwords.filter(p => {
    const matchesSearch = p.service.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          p.username.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = selectedCategory === 'All' || p.category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  if (screen === 'loading') {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100vh', background: '#1a1a2e', color: 'white' }}>
        <div style={{ fontSize: '4rem' }}>🔐</div>
        <p>Loading...</p>
      </div>
    );
  }

  if (screen === 'error') {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100vh', background: '#1a1a2e', color: 'white', padding: '20px' }}>
        <h1>⚠️ Connection Error</h1>
        <p style={{ color: '#dc3545', marginBottom: '20px' }}>{connectionError}</p>
        <p style={{ fontSize: '0.9rem', marginBottom: '20px' }}>
          Run this command in a terminal:<br/>
          <code style={{ background: '#333', color: '#fff', padding: '10px', display: 'block', marginTop: '10px', borderRadius: '4px' }}>
            cd backend && python -m uvicorn app:app --port 8000
          </code>
        </p>
        <button onClick={() => { setScreen('loading'); checkStatus(); }} style={{ padding: '10px 20px', cursor: 'pointer' }}>Retry Connection</button>
      </div>
    );
  }

  if (screen === 'setup') {
    return <SetupScreen onComplete={() => setScreen('login')} setError={setError} error={error} />;
  }

  if (screen === 'login') {
    return <LoginScreen onSuccess={() => { loadData(); setScreen('main'); }} setError={setError} error={error} />;
  }

  return (
    <div className={`container ${theme}`}>
      <Header theme={theme} setTheme={setTheme} onLogout={handleLogout} onRefresh={loadData} />
      <SearchBar
        searchTerm={searchTerm}
        setSearchTerm={setSearchTerm}
        selectedCategory={selectedCategory}
        setSelectedCategory={setSelectedCategory}
        categories={categories}
      />
      <PasswordList
        passwords={filteredPasswords}
        categories={categories}
        onRefresh={loadData}
      />
      <AddButton categories={categories} onAdd={loadData} />
    </div>
  );
}

// Setup Screen
function SetupScreen({ onComplete, setError, error }: { onComplete: () => void; setError: (e: string) => void; error: string }) {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSetup = async () => {
    if (password.length < 6) {
      setError('Password must be at least 6 characters');
      return;
    }
    if (password !== confirm) {
      setError('Passwords do not match');
      return;
    }
    setLoading(true);
    try {
      await api.setup(password);
      onComplete();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Setup failed');
    }
    setLoading(false);
  };

  return (
    <div className="container auth-screen">
      <div className="auth-box">
        <h1>🔐 Password Manager</h1>
        <p>Create a master password to secure your vault</p>
        {error && <div className="error">{error}</div>}
        <input type="password" placeholder="Master Password" value={password} onChange={e => setPassword(e.target.value)} />
        <input type="password" placeholder="Confirm Password" value={confirm} onChange={e => setConfirm(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleSetup()} />
        <button onClick={handleSetup} disabled={loading}>{loading ? 'Creating...' : 'Create Vault'}</button>
      </div>
    </div>
  );
}

// Login Screen
function LoginScreen({ onSuccess, setError, error }: { onSuccess: () => void; setError: (e: string) => void; error: string }) {
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLogin = async () => {
    setLoading(true);
    try {
      await api.login(password);
      onSuccess();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Login failed');
    }
    setLoading(false);
  };

  return (
    <div className="container auth-screen">
      <div className="auth-box">
        <h1>🔐 Password Manager</h1>
        <p>Enter your master password</p>
        {error && <div className="error">{error}</div>}
        <input type="password" placeholder="Master Password" value={password} onChange={e => setPassword(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleLogin()} autoFocus />
        <button onClick={handleLogin} disabled={loading}>{loading ? 'Unlocking...' : 'Unlock'}</button>
      </div>
    </div>
  );
}

// Header
function Header({ theme, setTheme, onLogout, onRefresh }: { theme: string; setTheme: (t: 'light' | 'dark') => void; onLogout: () => void; onRefresh: () => void }) {
  const toggleTheme = () => {
    const newTheme = theme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
    api.updateSetting('theme', newTheme);
  };

  return (
    <header>
      <h1>🔐 Password Manager</h1>
      <div className="header-actions">
        <button onClick={onRefresh} title="Refresh">🔄</button>
        <button onClick={toggleTheme} title="Toggle Theme">{theme === 'light' ? '🌙' : '☀️'}</button>
        <button onClick={onLogout} title="Lock">🔒</button>
      </div>
    </header>
  );
}

// Search Bar
function SearchBar({ searchTerm, setSearchTerm, selectedCategory, setSelectedCategory, categories }: {
  searchTerm: string; setSearchTerm: (s: string) => void;
  selectedCategory: string; setSelectedCategory: (s: string) => void;
  categories: Category[];
}) {
  return (
    <div className="search-bar">
      <input type="text" placeholder="🔍 Search passwords..." value={searchTerm} onChange={e => setSearchTerm(e.target.value)} />
      <select value={selectedCategory} onChange={e => setSelectedCategory(e.target.value)}>
        <option value="All">All Categories</option>
        {categories.map(c => <option key={c.id} value={c.name}>{c.name}</option>)}
      </select>
    </div>
  );
}


// Password List
function PasswordList({ passwords, categories, onRefresh }: { passwords: PasswordEntry[]; categories: Category[]; onRefresh: () => void }) {
  const [selected, setSelected] = useState<PasswordEntry | null>(null);
  const [showPassword, setShowPassword] = useState<{ [key: number]: boolean }>({});
  const [editingId, setEditingId] = useState<number | null>(null);

  const copyToClipboard = (text: string, type: string) => {
    navigator.clipboard.writeText(text);
    alert(`${type} copied to clipboard!`);
  };

  const handleDelete = async (id: number) => {
    if (confirm('Delete this password?')) {
      await api.deletePassword(id);
      onRefresh();
    }
  };

  const togglePassword = (id: number) => {
    setShowPassword(prev => ({ ...prev, [id]: !prev[id] }));
  };

  if (passwords.length === 0) {
    return <div className="empty-state"><p>No passwords yet. Click + to add one!</p></div>;
  }

  return (
    <div className="password-list">
      {passwords.map(p => (
        <div key={p.id} className="password-card" onClick={() => setSelected(selected?.id === p.id ? null : p)}>
          <div className="card-header">
            <span className="icon">{p.icon}</span>
            <div className="card-info">
              <strong>{p.service}</strong>
              <span className="username">{p.username}</span>
            </div>
            <span className="category-badge">{p.category}</span>
          </div>

          {selected?.id === p.id && (
            <div className="card-details">
              <div className="password-row">
                <input type={showPassword[p.id] ? 'text' : 'password'} value={p.password} readOnly />
                <button onClick={(e) => { e.stopPropagation(); togglePassword(p.id); }}>{showPassword[p.id] ? '🙈' : '👁'}</button>
                <button onClick={(e) => { e.stopPropagation(); copyToClipboard(p.password, 'Password'); }}>📋</button>
              </div>
              <button className="copy-user" onClick={(e) => { e.stopPropagation(); copyToClipboard(p.username, 'Username'); }}>📋 Copy Username</button>
              {p.notes && <p className="notes">{p.notes}</p>}
              <div className="card-actions">
                <button onClick={(e) => { e.stopPropagation(); setEditingId(p.id); }}>✏️ Edit</button>
                <button onClick={(e) => { e.stopPropagation(); handleDelete(p.id); }}>🗑️ Delete</button>
                <HistoryButton passwordId={p.id} />
                <TwoFAButton passwordId={p.id} />
              </div>
            </div>
          )}
        </div>
      ))}

      {editingId && (
        <EditModal
          password={passwords.find(p => p.id === editingId)!}
          categories={categories}
          onClose={() => setEditingId(null)}
          onSave={onRefresh}
        />
      )}
    </div>
  );
}

// History Button
function HistoryButton({ passwordId }: { passwordId: number }) {
  const [history, setHistory] = useState<{ password: string; changed_at: string }[] | null>(null);
  const [show, setShow] = useState(false);

  const loadHistory = async () => {
    const res = await api.getPasswordHistory(passwordId);
    setHistory(res.history);
    setShow(true);
  };

  return (
    <>
      <button onClick={(e) => { e.stopPropagation(); loadHistory(); }}>📜 History</button>
      {show && (
        <div className="modal" onClick={() => setShow(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <h3>Password History</h3>
            {history?.length === 0 ? <p>No history</p> : (
              <ul>{history?.map((h, i) => <li key={i}>{h.password} - {new Date(h.changed_at).toLocaleString()}</li>)}</ul>
            )}
            <button onClick={() => setShow(false)}>Close</button>
          </div>
        </div>
      )}
    </>
  );
}

// 2FA Button
function TwoFAButton({ passwordId }: { passwordId: number }) {
  const [show, setShow] = useState(false);
  const [text, setText] = useState('');

  const load2FA = async () => {
    const res = await api.get2FACodes(passwordId);
    setText(res.codes.join('\n'));
    setShow(true);
  };

  const save = async () => {
    const newCodes = text.split('\n').filter(c => c.trim());
    await api.save2FACodes(passwordId, newCodes);
    setShow(false);
  };

  return (
    <>
      <button onClick={(e) => { e.stopPropagation(); load2FA(); }}>🔑 2FA</button>
      {show && (
        <div className="modal" onClick={() => setShow(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <h3>2FA Backup Codes</h3>
            <textarea value={text} onChange={e => setText(e.target.value)} rows={6} placeholder="Enter 2FA codes, one per line" />
            <div className="modal-actions">
              <button onClick={save}>Save</button>
              <button onClick={() => setShow(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}


// Edit Modal
function EditModal({ password, categories, onClose, onSave }: { password: PasswordEntry; categories: Category[]; onClose: () => void; onSave: () => void }) {
  const [service, setService] = useState(password.service);
  const [username, setUsername] = useState(password.username);
  const [pwd, setPwd] = useState(password.password);
  const [notes, setNotes] = useState(password.notes);
  const [categoryId, setCategoryId] = useState(password.category_id || 0);
  const [loading, setLoading] = useState(false);

  const handleSave = async () => {
    setLoading(true);
    await api.updatePassword(password.id, { service, username, password: pwd, notes, category_id: categoryId || undefined });
    onSave();
    onClose();
    setLoading(false);
  };

  return (
    <div className="modal" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()}>
        <h3>Edit Password</h3>
        <input placeholder="Service" value={service} onChange={e => setService(e.target.value)} />
        <input placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} />
        <input type="password" placeholder="Password" value={pwd} onChange={e => setPwd(e.target.value)} />
        <select value={categoryId} onChange={e => setCategoryId(Number(e.target.value))}>
          <option value={0}>Select Category</option>
          {categories.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
        <textarea placeholder="Notes" value={notes} onChange={e => setNotes(e.target.value)} rows={3} />
        <div className="modal-actions">
          <button onClick={handleSave} disabled={loading}>{loading ? 'Saving...' : 'Save'}</button>
          <button onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

// Add Button & Modal
function AddButton({ categories, onAdd }: { categories: Category[]; onAdd: () => void }) {
  const [show, setShow] = useState(false);
  const [service, setService] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [notes, setNotes] = useState('');
  const [categoryId, setCategoryId] = useState(0);
  const [codes, setCodes] = useState('');
  const [strength, setStrength] = useState({ score: 0, label: '', color: '#ccc' });
  const [loading, setLoading] = useState(false);

  const checkStrength = async (pwd: string) => {
    if (pwd) {
      const res = await api.checkPasswordStrength(pwd);
      setStrength(res);
    } else {
      setStrength({ score: 0, label: '', color: '#ccc' });
    }
  };

  const generatePwd = async () => {
    const res = await api.generatePassword(16, true);
    setPassword(res.password);
    checkStrength(res.password);
  };

  const handleAdd = async () => {
    if (!service || !username || !password) return;
    setLoading(true);
    await api.addPassword({
      service, username, password, notes,
      category_id: categoryId || undefined,
      two_factor_codes: codes ? codes.split('\n').filter(c => c.trim()) : undefined
    });
    onAdd();
    setShow(false);
    // Reset form
    setService(''); setUsername(''); setPassword(''); setNotes(''); setCategoryId(0); setCodes('');
    setLoading(false);
  };

  return (
    <>
      <button className="add-btn" onClick={() => setShow(true)}>+</button>
      {show && (
        <div className="modal" onClick={() => setShow(false)}>
          <div className="modal-content large" onClick={e => e.stopPropagation()}>
            <h3>Add New Password</h3>
            <input placeholder="Service (e.g., Google)" value={service} onChange={e => setService(e.target.value)} />
            <input placeholder="Username / Email" value={username} onChange={e => setUsername(e.target.value)} />
            <div className="password-input">
              <input type="password" placeholder="Password" value={password} onChange={e => { setPassword(e.target.value); checkStrength(e.target.value); }} />
              <button type="button" onClick={generatePwd}>🎲</button>
            </div>
            <div className="strength-bar">
              <div style={{ width: `${strength.score}%`, backgroundColor: strength.color }}></div>
            </div>
            <span className="strength-label" style={{ color: strength.color }}>{strength.label}</span>
            <select value={categoryId} onChange={e => setCategoryId(Number(e.target.value))}>
              <option value={0}>Select Category</option>
              {categories.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
            <textarea placeholder="Notes (optional)" value={notes} onChange={e => setNotes(e.target.value)} rows={2} />
            <textarea placeholder="2FA Codes (one per line, optional)" value={codes} onChange={e => setCodes(e.target.value)} rows={3} />
            <div className="modal-actions">
              <button onClick={handleAdd} disabled={loading || !service || !username || !password}>
                {loading ? 'Adding...' : 'Add Password'}
              </button>
              <button onClick={() => setShow(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

export default App;
