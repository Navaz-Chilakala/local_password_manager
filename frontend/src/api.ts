const API_URL = 'http://localhost:8000/api';

let sessionId: string | null = localStorage.getItem('session_id');

export const setSession = (id: string | null) => {
  sessionId = id;
  if (id) {
    localStorage.setItem('session_id', id);
  } else {
    localStorage.removeItem('session_id');
  }
};

export const getSession = () => sessionId;

async function request(endpoint: string, options: RequestInit = {}) {
  const url = `${API_URL}${endpoint}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });
  
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Request failed');
  }
  
  return response.json();
}

export const api = {
  getStatus: () => request('/status'),
  
  setup: (masterPassword: string) => 
    request('/setup', { method: 'POST', body: JSON.stringify({ master_password: masterPassword }) }),
  
  login: async (masterPassword: string) => {
    const result = await request('/login', { method: 'POST', body: JSON.stringify({ master_password: masterPassword }) });
    if (result.session_id) {
      setSession(result.session_id);
    }
    return result;
  },
  
  logout: () => {
    const result = request(`/logout?session_id=${sessionId}`, { method: 'POST' });
    setSession(null);
    return result;
  },
  
  getPasswords: () => request(`/passwords?session_id=${sessionId}`),
  
  addPassword: (data: {
    service: string;
    username: string;
    password: string;
    notes?: string;
    category_id?: number;
    two_factor_codes?: string[];
  }) => request(`/passwords?session_id=${sessionId}`, { method: 'POST', body: JSON.stringify(data) }),
  
  updatePassword: (id: number, data: {
    service: string;
    username: string;
    password: string;
    notes?: string;
    category_id?: number;
  }) => request(`/passwords/${id}?session_id=${sessionId}`, { method: 'PUT', body: JSON.stringify(data) }),
  
  deletePassword: (id: number) => 
    request(`/passwords/${id}?session_id=${sessionId}`, { method: 'DELETE' }),
  
  getCategories: () => request(`/categories?session_id=${sessionId}`),
  
  addCategory: (name: string) => 
    request(`/categories?session_id=${sessionId}`, { method: 'POST', body: JSON.stringify({ name }) }),
  
  getPasswordHistory: (id: number) => request(`/passwords/${id}/history?session_id=${sessionId}`),
  
  get2FACodes: (id: number) => request(`/passwords/${id}/2fa?session_id=${sessionId}`),
  
  save2FACodes: (id: number, codes: string[]) => 
    request(`/passwords/${id}/2fa?session_id=${sessionId}`, { method: 'POST', body: JSON.stringify({ codes }) }),
  
  getSettings: () => request(`/settings?session_id=${sessionId}`),
  
  updateSetting: (key: string, value: string) => 
    request(`/settings?session_id=${sessionId}`, { method: 'PUT', body: JSON.stringify({ key, value }) }),
  
  generatePassword: (length = 16, includeSpecial = true) => 
    request(`/generate-password?length=${length}&include_special=${includeSpecial}`),
  
  checkPasswordStrength: (password: string) => 
    request(`/password-strength?password=${encodeURIComponent(password)}`),
};

