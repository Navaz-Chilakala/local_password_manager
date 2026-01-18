export interface PasswordEntry {
  id: number;
  service: string;
  username: string;
  password: string;
  notes: string;
  category: string;
  category_id: number | null;
  icon: string;
  created_at: string;
  updated_at: string;
}

export interface Category {
  id: number;
  name: string;
}

export interface PasswordHistory {
  password: string;
  changed_at: string;
}

export interface Settings {
  theme: string;
  auto_lock_minutes: string;
  password_expiry_days: string;
}

export interface PasswordStrength {
  score: number;
  label: string;
  color: string;
}

