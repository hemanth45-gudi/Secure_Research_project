"""
test_jwt.py   JWT Endpoint Verification
Tests both the JSON API behavior and the browser (cookie) auth behavior.
"""
import requests
import sys

BASE   = 'http://localhost:5000'
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

if __name__ == '__main__':
    print('\n=== Browser page-route tests (no token -> expect 302 redirect to /login) ===')

    # Test 1: No token, browser navigation -> server redirects to /login (302)
    try:
        r = requests.get(f'{BASE}/dashboard', allow_redirects=False, timeout=4)
        chk('No-token /dashboard: browser nav -> 302 redirect', r.status_code == 302, f'got {r.status_code}')
        chk('Redirect points to /login', '/login' in r.headers.get('Location', ''), r.headers.get('Location'))
    except Exception as e:
        chk('No-token /dashboard', False, str(e))

    # Test 2: No token, API client (sends Accept: application/json) -> 401 JSON
    try:
        r = requests.get(f'{BASE}/dashboard',
                        headers={'Accept': 'application/json'},
                        allow_redirects=False, timeout=4)
        body = r.json()
        chk('No-token API client /dashboard -> 401 JSON', r.status_code == 401, f'got {r.status_code}')
        chk('API client code=TOKEN_MISSING', body.get('code') == 'TOKEN_MISSING', str(body))
    except Exception as e:
        chk('No-token API client /dashboard', False, str(e))

    print('\n=== /api/v1/auth/login tests ===')

    # Test 3: Bad credentials -> 401 JSON
    try:
        r = requests.post(f'{BASE}/api/v1/auth/login',
                        json={'username': 'nobody', 'password': 'WrongPass123'}, timeout=4)
        body = r.json()
        chk('Bad creds /api/v1/auth/login -> 401', r.status_code == 401, f'got {r.status_code}')
        chk('Bad creds code=INVALID_CREDENTIALS', body.get('code') == 'INVALID_CREDENTIALS', str(body))
    except Exception as e:
        chk('Bad creds', False, str(e))

    print('\n=== Invalid Bearer token tests ===')

    # Test 4: Fake Bearer token -> 401 TOKEN_INVALID
    try:
        r = requests.get(f'{BASE}/dashboard',
                        headers={'Authorization': 'Bearer notarealtoken'}, timeout=4)
        body = r.json()
        chk('Fake Bearer token -> 401', r.status_code == 401, f'got {r.status_code}')
        chk('Fake Bearer code=TOKEN_INVALID', body.get('code') == 'TOKEN_INVALID', str(body))
    except Exception as e:
        chk('Fake Bearer token', False, str(e))

    # Test 5: Role-protected route with no token: browser nav -> 302
    try:
        r = requests.get(f'{BASE}/logs', allow_redirects=False, timeout=4)
        chk('No-token /logs -> 302 redirect', r.status_code == 302, f'got {r.status_code}')
    except Exception as e:
        chk('No-token /logs', False, str(e))

    print('\n=== Refresh & Logout tests ===')

    # Test 6: Bad refresh token -> 401
    try:
        r = requests.post(f'{BASE}/api/v1/auth/refresh',
                        json={'refresh_token': 'badtoken'}, timeout=4)
        chk('Bad refresh token -> 401', r.status_code == 401, f'got {r.status_code}')
    except Exception as e:
        chk('Bad refresh token', False, str(e))

    # Test 7: Logout (no body) -> 200 and cookie cleared
    try:
        r = requests.post(f'{BASE}/api/v1/auth/logout', json={}, timeout=4)
        chk('Logout -> 200', r.status_code == 200, f'got {r.status_code}')
        # Check Set-Cookie clears the cookie
        cookie_header = r.headers.get('Set-Cookie', '')
        chk('Logout clears srp_access_token cookie', 'srp_access_token' in cookie_header, cookie_header)
    except Exception as e:
        chk('Logout', False, str(e))


    print(f'\nResults: {passed} passed, {failed} failed\n')
    sys.exit(0 if failed == 0 else 1)
