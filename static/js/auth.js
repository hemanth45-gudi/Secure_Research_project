/**
 * auth.js   Client-side JWT Helper
 * ==================================
 * Provides:
 *   saveTokens(access, refresh)  - Store both tokens in localStorage
 *   getAccessToken()             - Retrieve access token
 *   getRefreshToken()            - Retrieve refresh token
 *   clearTokens()                - Remove tokens (logout)
 *   authFetch(url, options)      - Fetch wrapper with auto Bearer + refresh logic
 *   loginWithCredentials(u, p)   - POST to /api/login, save tokens, redirect
 *   logout()                     - POST to /api/logout, clear tokens, redirect
 */

const TOKEN_KEYS = {
  access:  'srp_access_token',
  refresh: 'srp_refresh_token',
};

// --  Storage ---------------------------------------------- 
export function saveTokens(accessToken, refreshToken) {
  localStorage.setItem(TOKEN_KEYS.access,  accessToken);
  localStorage.setItem(TOKEN_KEYS.refresh, refreshToken);
}

export function getAccessToken() {
  return localStorage.getItem(TOKEN_KEYS.access);
}

export function getRefreshToken() {
  return localStorage.getItem(TOKEN_KEYS.refresh);
}

export function clearTokens() {
  localStorage.removeItem(TOKEN_KEYS.access);
  localStorage.removeItem(TOKEN_KEYS.refresh);
}

// --  Authenticated Fetch (auto refresh on 401) ------------ 
/**
 * Drop-in replacement for fetch() that automatically:
 *  1. Attaches Authorization: Bearer <access_token>
 *  2. On 401 TOKEN_EXPIRED -> silently refreshes and retries once
 *  3. On second 401 -> clears tokens and redirects to /login
 */
export async function authFetch(url, options = {}) {
  options.headers = options.headers || {};
  options.headers['Authorization'] = `Bearer ${getAccessToken()}`;
  options.headers['Content-Type']  = options.headers['Content-Type'] || 'application/json';

  let response = await fetch(url, options);

  // Try to refresh once on expiry
  if (response.status === 401) {
    const body = await response.clone().json().catch(() => ({}));
    if (body.code === 'TOKEN_EXPIRED') {
      const refreshed = await _refreshAccessToken();
      if (refreshed) {
        options.headers['Authorization'] = `Bearer ${getAccessToken()}`;
        response = await fetch(url, options);
      } else {
        clearTokens();
        window.location.href = '/login';
        return;
      }
    }
  }

  return response;
}

// --  Internal: Refresh Access Token ------------------------
async function _refreshAccessToken() {
  const refreshToken = getRefreshToken();
  if (!refreshToken) return false;

  try {
    const res = await fetch('/api/token/refresh', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ refresh_token: refreshToken }),
    });

    if (!res.ok) return false;

    const data = await res.json();
    if (data.access_token) {
      localStorage.setItem(TOKEN_KEYS.access, data.access_token);
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

// --  Login ------------------------------------------------ 
/**
 * Calls POST /api/login, stores tokens, redirects to /dashboard.
 * Returns { success, error } for caller to show UI feedback.
 */
export async function loginWithCredentials(username, password) {
  try {
    const res = await fetch('/api/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username, password }),
    });

    const data = await res.json();

    if (res.ok && data.access_token) {
      saveTokens(data.access_token, data.refresh_token);
      window.location.href = '/dashboard';
      return { success: true };
    }

    return { success: false, error: data.error || 'Login failed' };
  } catch (err) {
    return { success: false, error: 'Network error. Please try again.' };
  }
}

// --  Logout ------------------------------------------------
/**
 * Revokes refresh token on server and clears local storage.
 */
export async function logout() {
  const refreshToken = getRefreshToken();

  if (refreshToken) {
    await fetch('/api/logout', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ refresh_token: refreshToken }),
    }).catch(() => {});  // Best-effort   always clear locally
  }

  clearTokens();
  window.location.href = '/login';
}
