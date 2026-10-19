// src/client/auth.tsx
import React, { useCallback, useEffect, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';

interface Me { id: string; role: string }

const TOKEN_KEY = 'gt_token';
let token: string | null = null;
try { token = sessionStorage.getItem(TOKEN_KEY); } catch { /* storage unavailable */ }
let onUnauthorized: (() => void) | null = null;

function saveToken(t: string | null) {
  token = t;
  try { t ? sessionStorage.setItem(TOKEN_KEY, t) : sessionStorage.removeItem(TOKEN_KEY); } catch { /* ignore */ }
}

/**
 * Wraps window.fetch for same-origin /api/ calls: attaches the bearer token, signs the user out on 401,
 * and turns a 403 on a GET into an empty list so dashboard panels the role may not see render empty
 * instead of crashing. (Cleaner long-term: replace fetch() calls in App.tsx with an apiFetch helper.)
 */
export function installAuthFetch() {
  const original = window.fetch.bind(window);
  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.pathname : input.url;
    if (!url.startsWith('/api/') || url.startsWith('/api/v1/auth/login')) return original(input, init);

    const headers = new Headers(init?.headers);
    if (token) headers.set('Authorization', `Bearer ${token}`);
    const res = await original(input, { ...init, headers });

    if (res.status === 401) onUnauthorized?.();
    if (res.status === 403 && (init?.method ?? 'GET').toUpperCase() === 'GET') {
      return new Response(url.startsWith('/api/v1/metrics') ? 'null' : '[]', {
        status: 200, headers: { 'Content-Type': 'application/json' },
      });
    }
    return res;
  };
}

export function AuthGate({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [checking, setChecking] = useState<boolean>(Boolean(token));
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const signOut = useCallback(() => { saveToken(null); setMe(null); }, []);

  useEffect(() => {
    onUnauthorized = signOut;
    if (!token) return;
    fetch('/api/v1/auth/me')
      .then((r) => (r.ok ? r.json() : null))
      .then((u) => setMe(u))
      .catch(() => setMe(null))
      .finally(() => setChecking(false));
    return () => { onUnauthorized = null; };
  }, [signOut]);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setBusy(true);
    setError('');
    try {
      const res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: form.get('username'), password: form.get('password') }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Sign-in failed');
      saveToken(data.token);
      setMe(data.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign-in failed');
    } finally {
      setBusy(false);
    }
  }

  if (checking) return null;

  if (!me) {
    return (
      <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', fontFamily: 'Manrope, system-ui, sans-serif' }}>
        <form onSubmit={onSubmit} style={{ display: 'grid', gap: 12, width: 320, padding: 24, border: '1px solid #d0d5dd', borderRadius: 12 }}>
          <h1 style={{ margin: 0, fontSize: 20 }}>GrainTrust sign-in</h1>
          <input name="username" placeholder="Username" autoComplete="username" required style={{ padding: 10 }} />
          <input name="password" type="password" placeholder="Password" autoComplete="current-password" required style={{ padding: 10 }} />
          {error && <div role="alert" style={{ color: '#b42318', fontSize: 14 }}>{error}</div>}
          <button type="submit" disabled={busy} style={{ padding: 10, cursor: 'pointer' }}>{busy ? 'Signing in…' : 'Sign in'}</button>
        </form>
      </div>
    );
  }

  return (
    <>
      {children}
      <div style={{ position: 'fixed', right: 12, bottom: 12, zIndex: 9999, background: '#101828', color: '#fff', padding: '6px 12px', borderRadius: 999, fontSize: 12, display: 'flex', gap: 10, alignItems: 'center' }}>
        <span>{me.id} · {me.role}</span>
        <button onClick={signOut} style={{ background: 'transparent', color: '#fff', border: '1px solid #fff5', borderRadius: 999, cursor: 'pointer', padding: '2px 8px' }}>Sign out</button>
      </div>
    </>
  );
}