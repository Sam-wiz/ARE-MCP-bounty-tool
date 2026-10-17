#!/usr/bin/env python3
"""Feed Secret manifests directly to kubectl stdin; no secret YAML on disk."""
import json
import os
import subprocess
from pathlib import Path

values = dict(line.split('=', 1) for line in Path('.env.local').read_text().splitlines() if '=' in line and not line.startswith('#'))
for k in ('API_TOKEN','MONGO_ROOT_PASSWORD','MONGO_APP_PASSWORD','REDIS_PASSWORD','GRAFANA_PASSWORD'):
    if not values.get(k):
        raise SystemExit(f'Missing {k}; run scripts/init_local_env.py')
secrets = {
    'app-secrets': {'API_TOKEN': values['API_TOKEN'], 'MONGODB_URI': f"mongodb://are_app:{values['MONGO_APP_PASSWORD']}@mongodb:27017/hack_ai_v2?authSource=hack_ai_v2", 'REDIS_PASSWORD': values['REDIS_PASSWORD']},
    'mongo-secrets': {'MONGO_INITDB_ROOT_USERNAME': 'root', 'MONGO_INITDB_ROOT_PASSWORD': values['MONGO_ROOT_PASSWORD'], 'MONGO_APP_PASSWORD': values['MONGO_APP_PASSWORD']},
    'redis-secrets': {'REDIS_PASSWORD': values['REDIS_PASSWORD']},
    'grafana-secrets': {'GF_SECURITY_ADMIN_PASSWORD': values['GRAFANA_PASSWORD']},
}
items=[{'apiVersion':'v1','kind':'Secret','metadata':{'name':name,'namespace':'are-mcp'},'type':'Opaque','stringData':data} for name,data in secrets.items()]
subprocess.run(['kubectl','--context',os.getenv('KUBE_CONTEXT','kind-are-mcp'), 'apply','--server-side','--field-manager=are-local-secrets','-f','-'],input=json.dumps({'apiVersion':'v1','kind':'List','items':items}),text=True,check=True)
