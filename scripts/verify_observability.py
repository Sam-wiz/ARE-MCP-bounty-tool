#!/usr/bin/env python3
"""Verify Prometheus samples, a provisioned dashboard, and an exported real trace."""
import base64
import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path

os.environ.setdefault('KUBECONFIG',str(Path('artifacts/kubeconfig').resolve()))
pids=[]

def get(url,headers=None):
    req=urllib.request.Request(url,headers=headers or {})
    with urllib.request.urlopen(req,timeout=10) as r:return json.load(r)
def wait_for(fn):
    until=time.monotonic()+90
    while time.monotonic()<until:
        try:
            value=fn()
            if value:return value
        except (OSError,ValueError,KeyError):pass
        time.sleep(2)
    raise RuntimeError('observability check timed out')

try:
    for name,port,remote in [('prometheus',19090,9090),('grafana',13000,3000),('jaeger',16687,16686)]:
        with open(f'artifacts/verify-{name}-forward.log','w') as log:
            pids.append(subprocess.Popen(['kubectl','--context','kind-are-mcp','-n','are-mcp','port-forward','--address=127.0.0.1','service/'+name,f'{port}:{remote}'],stdout=log,stderr=log))
    metrics=wait_for(lambda:get('http://127.0.0.1:19090/api/v1/query?query=are_rpc_requests_total')['data']['result'])
    values=dict(line.split('=',1) for line in Path('.env.local').read_text().splitlines() if '=' in line)
    auth=base64.b64encode(('admin:'+values['GRAFANA_PASSWORD']).encode()).decode()
    dashboard=wait_for(lambda:get('http://127.0.0.1:13000/api/dashboards/uid/are-overview',{'Authorization':'Basic '+auth})['dashboard'])
    smoke=json.loads(Path('artifacts/smoke.json').read_text())
    trace_id=next(e['trace_id'] for e in smoke['events'] if e['tool']=='ingest_result')
    traces=wait_for(lambda:get('http://127.0.0.1:16687/api/traces/'+trace_id)['data'])
    spans=traces[0]['spans']
    assert any(s['operationName']=='rpc tools/call' for s in spans)
    assert any(s['operationName']=='mongodb ping' for s in spans)
    assert any(s['operationName']=='redis ping' for s in spans)
    evidence={'status':'passed','timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'version':smoke['version'],'prometheus_series':len(metrics),'dashboard':dashboard['title'],'trace_id':trace_id,'span_names':[s['operationName'] for s in spans]}
    Path('artifacts/observability.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print(json.dumps(evidence,indent=2))
finally:
    for p in pids:
        p.terminate()
        try:p.wait(timeout=5)
        except subprocess.TimeoutExpired:p.kill();p.wait()
