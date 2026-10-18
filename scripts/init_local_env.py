#!/usr/bin/env python3
"""Create local-only random credentials. Never prints secret values."""
import os
import secrets
from pathlib import Path

path = Path('.env.local')
if path.exists():
    print('.env.local exists; keeping existing credentials.')
else:
    values = {k: secrets.token_hex(24) for k in (
        'API_TOKEN', 'MONGO_ROOT_PASSWORD', 'MONGO_APP_PASSWORD',
        'REDIS_PASSWORD', 'GRAFANA_PASSWORD')}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(''.join(f'{k}={v}\n' for k, v in values.items()))
    print('Created .env.local with random credentials (mode 0600).')
