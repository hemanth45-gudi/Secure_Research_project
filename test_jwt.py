import requests, sys

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

# Test 1: no token on protected route → 401
try:
    r = requests.get(f'{BASE}/dashboard', allow_redirects=False, timeout=4)
    chk('No-token /dashboard returns 401', r.status_code == 401, f'got {r.status_code}')
except Exception as e:
    chk('No-token /dashboard returns 401', False, str(e))

# Test 2: bad credentials → 401
try:
    r = requests.post(f'{BASE}/api/login', json={'username': 'nobody', 'password': 'wrong'}, timeout=4)
    body = r.json()
    chk('Bad creds /api/login returns 401', r.status_code == 401, f'got {r.status_code}')
    chk('Bad creds code=INVALID_CREDENTIALS', body.get('code') == 'INVALID_CREDENTIALS', str(body))
except Exception as e:
    chk('Bad creds', False, str(e))

# Test 3: invalid Bearer token → 401
try:
    r = requests.get(f'{BASE}/dashboard', headers={'Authorization': 'Bearer notarealtoken'}, timeout=4)
    body = r.json()
    chk('Invalid token /dashboard returns 401', r.status_code == 401, f'got {r.status_code}')
    chk('Invalid token code=TOKEN_INVALID', body.get('code') == 'TOKEN_INVALID', str(body))
except Exception as e:
    chk('Invalid token', False, str(e))

# Test 4: missing Authorization header → 401 with TOKEN_MISSING
try:
    r = requests.get(f'{BASE}/logs', timeout=4)
    body = r.json()
    chk('/logs no-token returns 401', r.status_code == 401, f'got {r.status_code}')
    chk('/logs code=TOKEN_MISSING', body.get('code') == 'TOKEN_MISSING', str(body))
except Exception as e:
    chk('/logs no-token', False, str(e))

# Test 5: bad refresh token → 401
try:
    r = requests.post(f'{BASE}/api/token/refresh', json={'refresh_token': 'badtoken'}, timeout=4)
    chk('Bad refresh token returns 401', r.status_code == 401, f'got {r.status_code}')
except Exception as e:
    chk('Bad refresh token', False, str(e))

# Test 6: logout with nonexistent token → 200
try:
    r = requests.post(f'{BASE}/api/logout', json={'refresh_token': 'doesnotexist'}, timeout=4)
    chk('Logout nonexistent token returns 200', r.status_code == 200, f'got {r.status_code}')
except Exception as e:
    chk('Logout', False, str(e))

print(f'\nResults: {passed} passed, {failed} failed')
sys.exit(0 if failed == 0 else 1)
