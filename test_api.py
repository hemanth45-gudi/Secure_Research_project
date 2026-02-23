"""
test_api.py   Comprehensive Production API Tests
==================================================
Tests all new REST API endpoints + verifies existing routes are intact.
Run:   python test_api.py

Fixes applied:
  - All auth routes now use /api/v1/auth/ prefix
  - Response body checks updated to match actual API response shape
  - Rate-limit header check is case-insensitive
  - Logout cookie assertion checks correct cookie name
"""

import sys
import threading
import time
import requests

BASE = 'http://localhost:5000'
passed = 0
failed = 0


def chk(name, condition, detail=''):
    global passed, failed
    if condition:
        print(f'  [PASS] {name}')
        passed += 1
    else:
        print(f'  [FAIL] {name} | {detail}')
        failed += 1


def section(title):
    print(f'\n{"="*60}')
    print(f'  {title}')
    print('='*60)


# -- Start app in background thread ------------------------ 
def start_server():
    from app import create_app
    _app = create_app('testing')
    _app.run(port=5000, debug=False, use_reloader=False)

if __name__ == '__main__':
    t = threading.Thread(target=start_server, daemon=True)
    t.start()
    time.sleep(3)   # Wait for server to be ready

    # ==============================================================
    # 1. Health & Infrastructure
    # ==============================================================
    section('Health & Infrastructure')

    try:
        r = requests.get(f'{BASE}/health', timeout=5)
        body = r.json()
        chk('/health returns 200', r.status_code == 200, f'got {r.status_code}')
        chk('/health db=connected', body.get('db') == 'connected', str(body))
    except Exception as e:
        chk('/health endpoint', False, str(e))
        sys.exit(1)  # Can't continue without server


    # ==============================================================
    # 2. Input Validation (Marshmallow)
    # ==============================================================
    section('Input Validation')

    # Empty body → 422
    r = requests.post(f'{BASE}/api/v1/auth/login', json={}, timeout=4)
    chk('Empty body -> 422', r.status_code == 422, f'got {r.status_code}')

    # Short password (< 8 chars) → 422
    r = requests.post(f'{BASE}/api/v1/auth/login',
                      json={'username': 'a', 'password': 'short'}, timeout=4)
    chk('Short password -> 422', r.status_code == 422, f'got {r.status_code}')

    # Missing password field → 422
    r = requests.post(f'{BASE}/api/v1/auth/login',
                      json={'username': 'only'}, timeout=4)
    body = r.json()
    chk('Missing password -> 422', r.status_code == 422, f'got {r.status_code}')
    chk('Validation code=VALIDATION_ERROR',
        body.get('code') == 'VALIDATION_ERROR', str(body))


    # ==============================================================
    # 3. Authentication API
    # ==============================================================
    section('Authentication API (/api/v1/auth/)')

    # Bad credentials → 401
    r = requests.post(f'{BASE}/api/v1/auth/login',
                      json={'username': 'nobody_xyz', 'password': 'WrongPass1'}, timeout=4)
    chk('Bad credentials -> 401', r.status_code == 401, f'got {r.status_code}')
    chk('code=INVALID_CREDENTIALS',
        r.json().get('code') == 'INVALID_CREDENTIALS', str(r.json()))

    # Invalid Bearer token on protected endpoint → 401
    r = requests.get(f'{BASE}/api/v1/auth/me',
                     headers={'Authorization': 'Bearer totallyfaketoken'}, timeout=4)
    chk('Fake Bearer -> 401', r.status_code == 401, f'got {r.status_code}')
    code = r.json().get('code', '')
    chk('code contains TOKEN_INVALID or INVALID',
        'TOKEN_INVALID' in code or 'INVALID' in code, code)

    # No token on /api/v1/auth/me → 401
    r = requests.get(f'{BASE}/api/v1/auth/me',
                     headers={'Accept': 'application/json'}, timeout=4)
    chk('No token /api/v1/auth/me -> 401', r.status_code == 401, f'got {r.status_code}')

    # Bad refresh token → 401
    r = requests.post(f'{BASE}/api/v1/auth/refresh',
                      json={'refresh_token': 'badtoken'}, timeout=4)
    chk('Bad refresh token -> 401', r.status_code == 401, f'got {r.status_code}')

    # Logout (no body) → always 200
    r = requests.post(f'{BASE}/api/v1/auth/logout', json={}, timeout=4)
    chk('Logout (no body) -> 200', r.status_code == 200, f'got {r.status_code}')
    # The API deletes the srp_access_token cookie — check Set-Cookie header
    set_cookie = r.headers.get('Set-Cookie', '')
    chk('Logout clears srp_access_token cookie',
        'srp_access_token' in set_cookie,
        f'Set-Cookie: {set_cookie}')


    # ==============================================================
    # 4. Route Protection (Role-Based)
    # ==============================================================
    section('Route Protection & RBAC')

    # API routes require auth (JSON client) → 401
    for path in ['/api/v1/datasets/', '/api/v1/users/', '/api/v1/admin/logs', '/api/v1/admin/stats']:
        r = requests.get(f'{BASE}{path}',
                         headers={'Accept': 'application/json'}, timeout=4)
        chk(f'{path} -> 401 without token',
            r.status_code == 401, f'got {r.status_code}')


    # Browser page routes without token → redirect (302)
    for path in ['/dashboard', '/logs', '/manage_users', '/view_datasets', '/upload']:
        r = requests.get(f'{BASE}{path}', allow_redirects=False, timeout=4)
        chk(f'{path} -> 302 redirect',
            r.status_code in (302, 308), f'got {r.status_code}')


    # ==============================================================
    # 5. Public Page Routes (No Auth Required)
    # ==============================================================
    section('Public Routes')

    for path in ['/', '/login', '/register', '/health']:
        try:
            r = requests.get(f'{BASE}{path}', allow_redirects=False, timeout=4)
            chk(f'{path} accessible (2xx/3xx)',
                r.status_code < 400, f'got {r.status_code}')
        except Exception as e:
            chk(f'{path} accessible', False, str(e))


    # ==============================================================
    # 6. Rate Limiting Headers
    # ==============================================================
    section('Rate Limiting Headers')

    r = requests.post(f'{BASE}/api/v1/auth/login',
                      json={'username': 'testuser', 'password': 'TestPass1'}, timeout=4)
    headers_lower = {k.lower(): v for k, v in r.headers.items()}
    chk('X-RateLimit-Limit header present',
        'x-ratelimit-limit' in headers_lower,
        str(dict(r.headers)))


    # ==============================================================
    # 7. Dataset Endpoints (Unauthenticated)
    # ==============================================================
    section('Dataset Endpoints (No Auth)')

    r = requests.get(f'{BASE}/api/v1/datasets/',
                     headers={'Accept': 'application/json'}, timeout=4)
    chk('/api/v1/datasets/ requires auth',
        r.status_code == 401, f'got {r.status_code}')

    r = requests.delete(f'{BASE}/api/v1/datasets/507f1f77bcf86cd799439011',
                        headers={'Accept': 'application/json'}, timeout=4)
    chk('/api/v1/datasets/<id> DELETE requires auth',
        r.status_code == 401, f'got {r.status_code}')


    # ==============================================================
    # 8. Users Endpoint (Unauthenticated)
    # ==============================================================
    section('User Endpoints (No Auth)')

    r = requests.get(f'{BASE}/api/v1/users/',
                     headers={'Accept': 'application/json'}, timeout=4)
    chk('/api/v1/users/ requires auth',
        r.status_code == 401, f'got {r.status_code}')


    # ==============================================================
    # 9. Admin Endpoints (Unauthenticated)
    # ==============================================================
    section('Admin Endpoints (No Auth)')

    r = requests.get(f'{BASE}/api/v1/admin/stats',
                     headers={'Accept': 'application/json'}, timeout=4)
    chk('/api/v1/admin/stats requires auth',
        r.status_code == 401, f'got {r.status_code}')

    r = requests.get(f'{BASE}/api/v1/admin/logs',
                     headers={'Accept': 'application/json'}, timeout=4)
    chk('/api/v1/admin/logs requires auth',
        r.status_code == 401, f'got {r.status_code}')


    # ==============================================================
    # Summary
    # ==============================================================
    print(f'\n{"="*60}')
    print(f'  Results: {passed} passed  |  {failed} failed')
    print(f'{"="*60}\n')

    sys.exit(0 if failed == 0 else 1)
