import { createContext, useContext, useEffect, useState } from 'react';
import { api } from './api/client';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .me()
      .then(setUser)
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  async function login(email, password) {
    const { user } = await api.login({ email, password });
    setUser(user);
  }

  async function register(email, password, full_name) {
    const { user } = await api.register({ email, password, full_name });
    setUser(user);
  }

  async function logout() {
    await api.logout().catch(() => {});
    setUser(null);
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>{children}</AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
