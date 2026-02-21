"""
core/cache.py   Redis-Backed Caching
======================================
Flask-Caching singleton.
  - Dev:  SimpleCache (no Redis required)
  - Prod: RedisCache
"""

from flask_caching import Cache

# Singleton   init_app() called from create_app()
cache = Cache()


# -- Helper wrappers ------------------------------------------

def cache_user(username: str, data: dict, timeout: int = 300):
    """Cache user profile (role, email) to avoid repeated DB hits."""
    cache.set(f'user:{username}', data, timeout=timeout)


def get_cached_user(username: str) -> dict | None:
    return cache.get(f'user:{username}')


def invalidate_user(username: str):
    cache.delete(f'user:{username}')


def cache_datasets(key: str, data, timeout: int = 300):
    cache.set(f'datasets:{key}', data, timeout=timeout)


def get_cached_datasets(key: str):
    return cache.get(f'datasets:{key}')


def invalidate_datasets(key: str = '*'):
    if key == '*':
        # Clear all dataset cache keys
        cache.clear()
    else:
        cache.delete(f'datasets:{key}')
