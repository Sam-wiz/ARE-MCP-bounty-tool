#!/usr/bin/env python3
"""Demonstrate dependency recovery, pod recovery, persisted state and rollback.
Only operates on this project's kind context and namespace. Restores state in finally.
"""
import json
import os
import subprocess
import time
import urllib.error
from pathlib import Path

os.environ.setdefault('KUBECONFIG', str(Path('artifacts/kubeconfig').resolve()))
os.environ['APP_URL']='http://127.0.0.1:18081'
import smoke

KUBE=['kubectl','--context','kind-are-mcp','-n','are-mcp']
def kube(*args):
    return subprocess.check_output(KUBE+list(args),text=True,timeout=180).strip()
def wait_for(predicate, timeout=120):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            if predicate(): return
        except (OSError, ValueError, urllib.error.URLError, subprocess.SubprocessError): pass
        time.sleep(2)
    raise RuntimeError('Timed out waiting for recovery condition')
def status(path):
    try: smoke.request(path);return 200
    except urllib.error.HTTPError as exc:return exc.code

def forward():
    log=open('artifacts/recovery-forward.log','a')
    p=subprocess.Popen(KUBE+['port-forward','--address=127.0.0.1','service/are-mcp','18081:8080'],stdout=log,stderr=log)
    log.close()
    try:
        wait_for(lambda:status('/readyz')==200)
    except BaseException:
        stop(p)
        raise
    return p

def stop(p):
    p.terminate()
    try:p.wait(timeout=5)
    except subprocess.TimeoutExpired:p.kill();p.wait()

Path('artifacts').mkdir(exist_ok=True)
p=None
original_image=kube('get','deployment','are-mcp','-o','jsonpath={.spec.template.spec.containers[0].image}')
evidence={'checks':[], 'image':original_image, 'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
try:
    p=forward()
    baseline=smoke.run()
    evidence['version']=baseline['version']
    started=time.monotonic()
    kube('scale','statefulset/redis','--replicas=0')
    wait_for(lambda:status('/readyz')==503,60)
    assert status('/healthz')==200
    evidence['checks'].append({'name':'dependency failure removes readiness but preserves liveness','status':'passed'})
    kube('scale','statefulset/redis','--replicas=1')
    kube('rollout','status','statefulset/redis','--timeout=120s')
    wait_for(lambda:status('/readyz')==200)
    evidence['dependency_recovery_seconds']=round(time.monotonic()-started,2)
    stop(p);p=None
    kube('rollout','restart','deployment/are-mcp')
    kube('rollout','status','deployment/are-mcp','--timeout=180s')
    p=forward()
    smoke.tool('set_program',{'slug':'cloud-demo'})
    result,_=smoke.tool('get_findings')
    assert any(f['id']==baseline['finding_id'] for f in json.loads(result['content'][0]['text']))
    evidence['checks'].append({'name':'finding survives application replacement','status':'passed','finding_id':baseline['finding_id']})
    stop(p);p=None
    kube('set','image','deployment/are-mcp','app=are-mcp:intentional-missing-release')
    def failed_release():
        data=json.loads(kube('get','pods','-l','app=are-mcp','-o','json'))
        return any(s.get('state',{}).get('waiting',{}).get('reason') in ('ErrImagePull','ImagePullBackOff') for item in data['items'] for s in item.get('status',{}).get('containerStatuses',[]))
    wait_for(failed_release,90)
    evidence['checks'].append({'name':'bad release detected as image pull failure','status':'passed'})
    kube('set','image','deployment/are-mcp','app='+original_image)
    kube('rollout','status','deployment/are-mcp','--timeout=180s')
    p=forward()
    assert smoke.request('/version')[0]==baseline['version']
    evidence['checks'].append({'name':'rollback restores exact previous version','status':'passed'})
    evidence['status']='passed'
finally:
    if p:stop(p)
    kube('scale','statefulset/redis','--replicas=1')
    kube('set','image','deployment/are-mcp','app='+original_image)
    Path('artifacts/recovery.json').write_text(json.dumps(evidence,indent=2)+'\n')
print(json.dumps(evidence,indent=2))
