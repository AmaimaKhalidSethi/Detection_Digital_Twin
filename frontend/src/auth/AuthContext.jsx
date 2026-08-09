import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { api, setCsrfToken, setUnauthorizedHandler } from "../lib/api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [status, setStatus] = useState("checking");

  useEffect(() => {
    const handleUnauthorized = () => {
      setCsrfToken(null);
      setUser(null);
      setStatus("unauthenticated");
    };
    setUnauthorizedHandler(handleUnauthorized);
    api.me()
      .then(({ user: currentUser }) => {
        setUser(currentUser);
        setStatus("authenticated");
      })
      .catch(handleUnauthorized);
    return () => setUnauthorizedHandler(null);
  }, []);

  const value = useMemo(() => ({
    user,
    status,
    async login(username, password) {
      const result = await api.login(username, password);
      setCsrfToken(result.csrf_token);
      setUser(result.user);
      setStatus("authenticated");
      return result.user;
    },
    async logout() {
      try {
        await api.logout();
      } finally {
        setCsrfToken(null);
        setUser(null);
        setStatus("unauthenticated");
      }
    },
  }), [user, status]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside AuthProvider");
  return context;
}
