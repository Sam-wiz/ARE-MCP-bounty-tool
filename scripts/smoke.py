#!/usr/bin/env python3
"""Exercise only synthetic local records; never sends traffic to a target."""
import json
import os
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

BASE = os.getenv('APP_URL', 'http://127.0.0.1:8080')
def token():
    if os.getenv('API_TOKEN'): return os.environ['API_TOKEN']
    values=dict(line.split('=',1) for line in Path('.env.local').read_text().splitlines() if '=' in line)
    return values['API_TOKEN']

def request(path, body=None, authenticated=True):
    headers={'Content-Type':'application/json'}
    if authenticated: headers['Authorization']='Bearer '+token()
    req=urllib.request.Request(BASE+path, data=json.dumps(body).encode() if body is not None else None, headers=headers)
    with urllib.request.urlopen(req,timeout=40) as response:
        data=response.read().decode()
        return json.loads(data) if data else None, dict(response.headers)

def rpc(method, params=None):
    value,headers=request('/rpc',{'jsonrpc':'2.0','id':str(uuid.uuid4()),'method':method,'params':params or {}})
    if value.get('error'): raise AssertionError(value['error'])
    result=value['result']
    if isinstance(result,dict) and result.get('isError'): raise AssertionError(result)
    return result,headers.get('X-Trace-Id',headers.get('X-Trace-ID'))

def tool(name,arguments=None):
    return rpc('tools/call',{'name':name,'arguments':arguments or {}})

def run():
    events=[]
    version,_=request('/version')
    assert request('/readyz')[0]['status']=='ready'
    try:
        request('/rpc',{'jsonrpc':'2.0','id':1,'method':'initialize'},False)
        raise AssertionError('unauthenticated request was accepted')
    except urllib.error.HTTPError as exc:
        assert exc.code==401
    result,trace=rpc('initialize');assert result['serverInfo']['name']=='hack-ai-v2'
    tools,_=rpc('tools/list');assert any(x['name']=='ingest_result' for x in tools['tools'])
    assert not any(x['name']=='execute_hunting_script' for x in tools['tools'])
    for name,args in [
      ('set_program',{'slug':'cloud-demo','name':'Local Cloud Demonstration','in_scope':['demo.example.test']}),
      ('set_target',{'domain':'demo.example.test'}),
      ('validate_scope',{'target':'demo.example.test'}),
    ]:
        started=time.monotonic();result,trace=tool(name,args)
        events.append({'tool':name,'trace_id':trace,'duration_ms':round((time.monotonic()-started)*1000,2)})
    title='Synthetic local finding '+str(uuid.uuid4())
    result,trace=tool('ingest_result',{'title':title,'severity':'info','vuln_type':'demo','description':'Synthetic record used only to verify persistence and report generation.'})
    events.append({'tool':'ingest_result','trace_id':trace})
    result,_=tool('get_findings')
    findings=json.loads(result['content'][0]['text'])
    match=next(x for x in findings if x['title']==title)
    report,_=tool('generate_report',{'format':'markdown'})
    assert title in report['content'][0]['text']
    evidence={'status':'passed','timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'version':version,'program':'cloud-demo','finding_id':match['id'],'finding_title':title,'events':events,'checks':['ready','authentication','tool allowlist','program','target','scope','ingestion','readback','report']}
    Path('artifacts').mkdir(exist_ok=True)
    Path('artifacts/smoke.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print(json.dumps(evidence,indent=2))
    return evidence

if __name__=='__main__': run()
