#!/usr/bin/env python3
"""Identify uncommitted source exactly without claiming it is a final commit."""
import hashlib
import json
import subprocess
from pathlib import Path

roots=['cmd','internal','plugins','config/config.example.yaml','deploy','scripts','.github','docs','Dockerfile','.dockerignore','go.mod','go.sum','Makefile','README.md','.gitignore','.env.example','compose.yaml']
files=[]
for root in roots:
    p=Path(root)
    files.extend(x for x in (p.rglob('*') if p.is_dir() else [p]) if x.is_file() and '__pycache__' not in x.parts)
manifest={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(set(files))}
digest=hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest()
head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
print(json.dumps({'baseline_commit':'8f65f098932831c4bf8429e5385446164f57d1be','head_commit':head,'source_sha256':digest,'image_tag':head[:12]+'-'+digest[:12], 'files':manifest},indent=2))
