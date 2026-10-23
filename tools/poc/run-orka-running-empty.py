#!/usr/bin/env python3
"""Bounded ordinary manager/public kmx/native tool/actual Guardd attempt.
No manual readiness, reconciler driving, workload launcher or status mutation.
Only deterministic external inference and independent receiver fixture processes.
"""
import argparse,secrets,base64,hashlib,json,os,shutil,socket,sqlite3,struct,subprocess,sys,time
from pathlib import Path
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--config',type=Path,required=True,help='Explicit private local paths/node/API coordinates; see ../../examples/poc/orka/config.example.json')
parser.add_argument('--check-inputs',action='store_true',help='Validate local declared files/trees/config only, never spawn a process or contact cluster')
a=parser.parse_args()
config_path=a.config.resolve(strict=True)
cfg=json.loads(config_path.read_text())
path_keys=['sources','manifest','kubeconfig','fixture_inputs','manager_command','workspace','artifact_root','manager_state_root','guardd_python','bpf_object','image_receipt','manager','kaimahi_cli','policy_envelope','output']
for key in path_keys:
 value=cfg[key]
 if not isinstance(value,str) or not Path(value).is_absolute():raise SystemExit('absolute explicit path required: '+key)
for key in ['kubeconfig','manifest','manager_command','guardd_python','bpf_object','image_receipt','manager','kaimahi_cli','policy_envelope']:
 if not Path(cfg[key]).is_file():raise SystemExit('required file missing/nonregular: '+key)
for key in ['sources','fixture_inputs','workspace','artifact_root','manager_state_root']:
 if not Path(cfg[key]).is_dir():raise SystemExit('required directory missing: '+key)
for key in ['node','cluster','context','namespace','runtime_namespace','node_enforcer_directory','node_api_url','node_ip','host_gateway_ip','image','scenario']:
 if not isinstance(cfg[key],str) or not cfg[key]:raise SystemExit('required coordinate: '+key)
if cfg['scenario'] not in ['allow','empty']:raise SystemExit('scenario must be allow or empty')
if not cfg['node_enforcer_directory'].startswith('/'):raise SystemExit('absolute node enforcer directory required')
if cfg.get('diagnostic_ptrace'):raise SystemExit('diagnostic tracing is not an acceptance scenario')
for item in ['seed.json','orka-same-policy-fixture.py']:
 if not (Path(cfg['fixture_inputs'])/item).is_file():raise SystemExit('missing fixture '+item)
for item in ['native_network.py','neutral_service.py']:
 if not (Path(cfg['sources'])/'guardd/src/agentsuite_guardd'/item).is_file():raise SystemExit('missing selected enforcer source '+item)
# An exact relocated source manifest, not assignment of an expected tree as proof.
manifest=json.loads(Path(cfg['manifest']).read_text());source_rows={x['repository']:x for x in manifest['rows']}
local_files={key:Path(cfg[key]) for key in ['manifest','manager_command','guardd_python','bpf_object','image_receipt','manager','kaimahi_cli','policy_envelope']}
local_files.update({'runner':Path(__file__),'fixture':Path(cfg['fixture_inputs'])/'orka-same-policy-fixture.py'})
for key,p in local_files.items():
 expected=cfg.get('expected_sha256',{}).get(key)
 if not expected or hashlib.sha256(p.read_bytes()).hexdigest()!=expected:raise SystemExit('missing/mismatched declared file digest: '+key)
def remap_seed(value):
 if isinstance(value,list):return [remap_seed(x) for x in value]
 if isinstance(value,dict):
  return {k:(cfg['namespace'] if k=='namespace' else remap_seed(v)) for k,v in value.items()}
 return value
seed=remap_seed(json.loads((Path(cfg['fixture_inputs'])/'seed.json').read_text()))
manager_template=json.loads(Path(cfg['manager_command']).read_text())
if not isinstance(manager_template,list) or not manager_template:raise SystemExit('manager command list required')
def manager_command():
 replacements={
 '--watch-namespace':cfg['namespace'],
 '--acp-runtime-namespace':cfg['runtime_namespace'],
 '--controller-url':'http://orka-api.'+cfg['namespace']+'.svc:8080',
 '--acp-provider-proxy-base-url':'http://provider.'+cfg['namespace']+'.svc:8080',
 '--acp-provider-proxy-namespace':cfg['namespace'],
 '--acp-enforcer-directory':cfg['node_enforcer_directory'],
 '--acp-codex-runtime-image':cfg['image'],
 '--store-path':str(Path(cfg['manager_state_root'])/'manager.db'),
 '--agent-execution-snapshot-key-file':str(Path(cfg['manager_state_root'])/'snapshot-key'),
 '--webhook-cert-path':str(Path(cfg['manager_state_root'])/'tls'),
 '--acp-provider-proxy-token-file':str(Path(cfg['manager_state_root'])/'provider-token')}
 seen=set();command=[cfg['manager']]
 for arg in manager_template[1:]:
  flag=arg.split('=',1)[0]
  if flag in replacements:
   if flag in seen:raise SystemExit('duplicate manager coordinate flag: '+flag)
   seen.add(flag);arg=flag+'='+replacements[flag]
  command.append(arg)
 missing=set(replacements)-seen
 if missing:raise SystemExit('missing manager coordinate flags: '+','.join(sorted(missing)))
 return command
managerargs=manager_command()
def kub_command(*args):return [cfg['kubectl'],'--context',cfg['context'],*args]
def public_command(workspace):
 return [cfg['kaimahi_cli'],'--context',cfg['context'],'run','--agent','sample','--namespace',cfg['namespace'],'--policy-workspace',str(workspace),'--prompt','Probe authored network ceiling then answer NETWORK_NATIVE_OK.','--wait','4m']
def host_node_path(pid,node_path):return Path('/proc')/str(pid)/'root'/node_path.lstrip('/')
if cfg['namespace']==cfg['runtime_namespace']:raise SystemExit('dedicated distinct task/runtime namespaces required')
for key in ['kubectl','docker','nsenter','fixture_python']:
 if not Path(cfg[key]).is_absolute() or not Path(cfg[key]).is_file() or not os.access(cfg[key],os.X_OK):raise SystemExit('required explicit executable: '+key)
 expected=cfg.get('expected_sha256',{}).get(key)
 if not expected or hashlib.sha256(Path(cfg[key]).read_bytes()).hexdigest()!=expected:raise SystemExit('missing/mismatched tool digest: '+key)
parent=Path(cfg['output']).parent
if not parent.is_dir() or not os.access(parent,os.W_OK):raise SystemExit('existing writable private output parent required')
if parent.stat().st_uid!=os.geteuid() or parent.stat().st_mode&0o077:raise SystemExit('private owned output parent required')
if os.path.lexists(cfg['output']):raise SystemExit('new output required')
if a.check_inputs:
 print(json.dumps({'classification':'local config/input digest preflight only; cluster, source trees, native NOT RUN','files':len(local_files),'config_sha256':hashlib.sha256(config_path.read_bytes()).hexdigest(),'plan':{'kubectl':kub_command('get','namespaces'), 'private_kubeconfig_command':kub_command('config','view','--raw','--flatten','--minify','-o','json'),'manager':managerargs,'public':public_command(Path(cfg['output'])/'workspace'),'host_node_directory_example':str(host_node_path(12345,cfg['node_enforcer_directory'])),'node_directory':cfg['node_enforcer_directory'],'seed':seed}},indent=2));raise SystemExit(0)
# Verify production trees before any cluster mutation. This uses git, not runtime work.
for repo in ['orka','guardd','kaimahi']:
 source=Path(cfg['sources'])/repo
 actual=subprocess.check_output(['git','-C',str(source),'write-tree'],text=True).strip()
 dirty=subprocess.check_output(['git','-C',str(source),'diff','--name-only'],text=True).strip()
 untracked=subprocess.check_output(['git','-C',str(source),'ls-files','--others','--exclude-standard'],text=True).strip()
 if actual!=source_rows[repo]['tree'] or dirty or untracked:raise SystemExit('not exact selected source: '+repo)
out=Path(cfg['output']).resolve();out.mkdir(mode=0o700)
node=cfg['node'];ns=cfg['namespace'];kube=Path(cfg['kubeconfig'])
r=Path(cfg['sources']);fixture_inputs=Path(cfg['fixture_inputs'])
env=dict(os.environ,KUBECONFIG=str(kube),POD_NAMESPACE=ns,ORKA_ACP_ARTIFACT_ROOT=cfg['artifact_root'],KAIMAHI_CONFIRM='yes')
children=[];logs=[];result={'classification':'normal public native integrated attempt, all actual exits retained','success':False,'runner_lineage':'parameterized from earlier parameterized runner; no new native run implied'}
def call(args,timeout=30,check=True):
 q=subprocess.run(args,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
 with (out/'commands.jsonl').open('a') as f:f.write(json.dumps(dict(command=args,exit_code=q.returncode,output=q.stdout.decode()))+'\n')
 if check and q.returncode:raise RuntimeError(q.stdout.decode()[-5000:])
 return q.stdout.decode().strip()
def kub(*args,**kw):return call(kub_command(*args),**kw)
def child(name,args,ce=env):
 log=(out/(name+'.log')).open('w');logs.append(log);p=subprocess.Popen(args,env=ce,stdout=log,stderr=subprocess.STDOUT);children.append((name,p));return p
def until(predicate,seconds):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  if predicate():return
  time.sleep(.3)
 raise TimeoutError('bounded prerequisite not ready')
assert os.geteuid()==0;assert call([cfg['docker'],'inspect','--format','{{index .Config.Labels "io.x-k8s.kind.cluster"}}',node])==cfg['cluster']
for root in [Path('/'),Path('/var/lib/docker'),out]:
 st=os.statvfs(root)
 assert st.f_bavail*st.f_frsize-64*1024**2>5*1024**3 and st.f_favail>=1024, 'projected root/Docker/output admission'

nodepid=int(call([cfg['docker'],'inspect','--format','{{.State.Pid}}',node]));peer=host_node_path(nodepid,cfg['node_enforcer_directory']);assert (peer/'config.json').is_file();assert not (peer/'socket').exists()
# Read-only cluster/node and dedicated namespace admission, no mutation or child.
node_record=json.loads(kub('get','node',node,'-o','json'))
if node_record['metadata']['name']!=node or not any(x.get('type')=='InternalIP' and x.get('address')==cfg['node_ip'] for x in node_record['status']['addresses']):raise SystemExit('configured context/node/IP mismatch')
for namespace in [ns,cfg['runtime_namespace']]:
 obj=json.loads(kub('get','namespace',namespace,'-o','json'))
 if obj['metadata']['name']!=namespace:raise SystemExit('namespace identity mismatch')
 if namespace==cfg['runtime_namespace'] and obj['metadata'].get('labels',{}).get('pod-security.kubernetes.io/enforce')!='privileged':raise SystemExit('dedicated runtime namespace lacks privileged admission')
 if namespace==ns and obj['metadata'].get('labels',{}).get('orka.ai/controller-mode')!='harness-v2':raise SystemExit('dedicated task namespace lacks ordinary harness-v2 ownership label')
for arg in managerargs:
 if arg.startswith('--acp-enforcer-node-labels='):
  for pair in arg.split('=',1)[1].split(','):
   key,value=pair.split('=',1)
   if node_record['metadata'].get('labels',{}).get(key)!=value:raise SystemExit('configured node selector mismatch')
for path in [peer,peer/'config.json']:
 st=path.stat()
 if st.st_uid!=0 or st.st_mode&0o022:raise SystemExit('protected root-owned node directory/config required')
for private_input in [Path(cfg['manager_state_root'])/'snapshot-key',Path(cfg['manager_state_root'])/'provider-token',Path(cfg['manager_state_root'])/'tls/tls.crt',Path(cfg['manager_state_root'])/'tls/tls.key']:
 if not private_input.is_file():raise SystemExit('missing private manager prerequisite: '+str(private_input))
conf=dict(socket=str(peer/'socket'),state=str(out/'peer.db'),pins='/sys/fs/bpf/poc-'+out.name,object=cfg['bpf_object']);assert not Path(conf['pins']).exists();(out/'provider.json').write_text(json.dumps(conf))
requirement=json.loads(Path(cfg['policy_envelope']).read_text());raw=base64.b64decode(requirement['bytes']);(out/'requirement.json').write_text(json.dumps(requirement,indent=2));result['classification']='public Orka network-independent entrypoint; TEST-only image, real native syscall; no inference success';result['guardd_tree']=source_rows['guardd']['tree'];result['orka_tree']=source_rows['orka']['tree'];result['policy_digest']=requirement['digest'];result['selected_kaimahi_cli']={'path':str(Path(cfg['kaimahi_cli']).resolve(strict=True)),'sha256':hashlib.sha256(Path(cfg['kaimahi_cli']).read_bytes()).hexdigest()}
workspace=out/'workspace';shutil.copytree(Path(cfg['workspace']),workspace);(workspace/'agents/greeter/policy.json').write_bytes(raw)
relay=seed['items'][-1];assert relay['metadata']['namespace']==ns;relay['metadata']['name']='native-relay-'+out.name[-8:];relay['spec']['activeDeadlineSeconds']=600
# Two ordinary Service endpoints in a bounded infrastructure Pod. Neither is
# the workload launcher; model bridge sits outside the governed native cgroup.
relay['spec']['containers'][0]['command']=['sh','-c',f"mkdir -p /tmp/cgi; printf '#!/bin/sh\nexec nc {cfg['node_ip']} 28980\n' > /tmp/cgi/api; printf '#!/bin/sh\nexec nc {cfg['host_gateway_ip']} 28990\n' > /tmp/cgi/model; chmod +x /tmp/cgi/*; nc -lkp 8082 -e /tmp/cgi/api & child=$!; trap 'kill $child; wait $child' EXIT; nc -lkp 8080 -e /tmp/cgi/model"]
relay['metadata']['labels']['orka.ai/network-role']='provider-auth-proxy';relay['metadata']['labels']['poc-fixture-run']=out.name
service=dict(apiVersion='v1',kind='Service',metadata=dict(name='provider',namespace=ns),spec=dict(selector={'poc-fixture-run':out.name},ports=[dict(name='model',port=8080,targetPort=8080)]))
api=dict(apiVersion='v1',kind='Service',metadata=dict(name='orka-api',namespace=ns,labels={'app.kubernetes.io/name':'orka'}),spec=dict(selector={'poc-fixture-run':out.name,'app.kubernetes.io/name':'orka','app.kubernetes.io/component':'controller'},ports=[dict(name='api',port=8080,targetPort=8082)]));(out/'fixtures.json').write_text(json.dumps(dict(apiVersion='v1',kind='List',items=[relay,service,api]),indent=2))
# Single configured context for kubectl, public kmx and derived manager kubeconfig.
rawk=json.loads(subprocess.check_output(kub_command('config','view','--raw','--flatten','--minify','-o','json'),env=env,timeout=15))
assert rawk['current-context']==cfg['context'] and len(rawk['clusters'])==1
rawk['clusters'][0]['cluster']['server']=cfg['node_api_url']
private_kubeconfig=out/'private-kubeconfig.json'
fd=os.open(private_kubeconfig,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as private:json.dump(rawk,private)
# Do not write raw flattened kubeconfig to command logs beyond this private file.
required=[config_path,Path(cfg['manager_command']),fixture_inputs/'seed.json',Path(__file__),Path(cfg['manager']),Path(cfg['kaimahi_cli']),Path(cfg['policy_envelope']),Path(conf['object']),r/'guardd/src/agentsuite_guardd/native_network.py',r/'guardd/src/agentsuite_guardd/neutral_service.py',Path(cfg['image_receipt']),fixture_inputs/'orka-same-policy-fixture.py',Path(conf['socket']).parent/'config.json']
required += [Path(cfg[key]) for key in ['kubectl','docker','nsenter','fixture_python']]
required += [p for p in Path(cfg['workspace']).rglob('*') if p.is_file()]
image_receipt=json.loads(Path(cfg['image_receipt']).read_text())
assert cfg['image'].endswith('@'+image_receipt['image_manifest'])
image_digest=image_receipt['image_manifest']
image_raw=subprocess.check_output([cfg['docker'],'exec',node,'ctr','-n','k8s.io','content','get',image_digest])
assert 'sha256:'+hashlib.sha256(image_raw).hexdigest()==image_digest
for desc in [json.loads(image_raw)['config']]+json.loads(image_raw)['layers']:
 blob=subprocess.check_output([cfg['docker'],'exec',node,'ctr','-n','k8s.io','content','get',desc['digest']])
 assert len(blob)==desc['size'] and 'sha256:'+hashlib.sha256(blob).hexdigest()==desc['digest']
initial_pod_uids={x['metadata']['uid'] for x in json.loads(kub('get','pods','-n',cfg['runtime_namespace'],'-o','json'))['items']}

try:
 prelaunch={str(p):{'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size} for p in required if p.is_file()}
 assert len(prelaunch)==len(required),'required prelaunch input missing'
 st=os.statvfs(out)
 assert st.f_bavail*st.f_frsize-32*1024**2>5*1024**3
 (out/'prelaunch.json').write_text(json.dumps({'files':prelaunch,'output_device':out.stat().st_dev,'available_bytes':st.f_bavail*st.f_frsize,'projected_bytes':64*1024**2,'root_docker_admission':[{'path':str(p),'device':p.stat().st_dev,'available_bytes':os.statvfs(p).f_bavail*os.statvfs(p).f_frsize} for p in [Path('/'),Path('/var/lib/docker'),out]],'image_receipt':image_receipt,'image':cfg['image']},indent=2))
 Path(conf['pins']).mkdir(mode=0o700)
 daemon=child('guardd',[cfg['guardd_python'],'-m','agentsuite_guardd.cli','--config',str(out/'provider.json'),'serve-enforcement'],dict(env,PYTHONPATH=str(r/'guardd/src'),PYTHONUNBUFFERED='1'))
 until(lambda:(peer/'socket').exists() or daemon.poll() is not None,20);assert daemon.poll() is None
 child('model',[cfg['fixture_python'],str(fixture_inputs/'orka-same-policy-fixture.py'),'model',str(out),'--model-host',cfg['host_gateway_ip']])
 kub('apply','-f',str(out/'fixtures.json'));kub('wait','--for=condition=Ready','pod/'+relay['metadata']['name'],'-n',ns,'--timeout=40s',timeout=50)
 leases=json.loads(kub('get','leases','-n',ns,'-o','json'))['items'];previous_epoch=max([int(x['metadata'].get('annotations',{}).get('core.orka.ai/controller-epoch','0')) for x in leases],default=0);result['previous_controller_epoch']=previous_epoch
 manager=child('manager',[cfg['nsenter'],'--target',str(nodepid),'--net','--']+managerargs,dict(env,KUBECONFIG=str(out/'private-kubeconfig.json')))
 before=json.loads(kub('get','tasks','-n',ns,'-o','json'));old={x['metadata']['uid'] for x in before['items']}
 def admitted():
  pools=json.loads(kub('get','runtimepools','-n',ns,'-o','json'))['items']
  return any(x.get('status',{}).get('controllerEpoch',0)>previous_epoch and cfg['image'] == x['spec']['runtime']['image'] and x.get('status',{}).get('admissionState')=='Accepting' and x.get('status',{}).get('activeInstance',{}).get('controllerEpoch')==max([p.get('status',{}).get('activeInstance',{}).get('controllerEpoch',0) for p in pools]) for x in pools)
 # Pools legitimately scale to zero while idle. Public submission, not a
 # fabricated admission state, is responsible for requesting ordinary scale-up.
 until(lambda: manager.poll() is not None or 'Starting workers' in (out/'manager.log').read_text(),30)
 if manager.poll() is not None:raise RuntimeError('normal manager stopped')
 args=public_command(workspace);(out/'kmx-command.json').write_text(json.dumps(args,indent=2))
 log=(out/'kmx.log').open('w');logs.append(log)
 q=subprocess.Popen(args,env=env,stdout=log,stderr=subprocess.STDOUT);children.append(('kmx',q))
 def running_pod():
  items=json.loads(kub('get','pods','-n',cfg['runtime_namespace'],'-o','json'))['items']
  return any(cfg['image'] == x['spec']['containers'][0]['image'] and x.get('status',{}).get('containerStatuses',[{}])[0].get('containerID') for x in items)
 until(running_pod,100)
 # Bind receiver fixture to the actual public Task's executing Pod, not an
 # idle or rolling predecessor that happens to share the same image.
 until(lambda:any(x['metadata']['uid'] not in old and x.get('status',{}).get('execution',{}).get('runtimeInstanceID') for x in json.loads(kub('get','tasks','-n',ns,'-o','json'))['items']),100)
 tasks=json.loads(kub('get','tasks','-n',ns,'-o','json'))['items']
 live=[x for x in tasks if x['metadata']['uid'] not in old and x.get('status',{}).get('execution',{}).get('runtimeInstanceID')]
 live.sort(key=lambda x:x['metadata']['creationTimestamp'])
 actual_uid=live[-1]['status']['execution']['runtimeInstanceID'].split('.')[0]
 pods=[x for x in json.loads(kub('get','pods','-n',cfg['runtime_namespace'],'-o','json'))['items'] if x['metadata']['uid']==actual_uid];assert len(pods)==1
 pod=pods[0];podname=pod['metadata']['name'];uid=pod['metadata']['uid'];container=pod['status']['containerStatuses'][0]['containerID'].split('://',1)[1]
 info=json.loads(call([cfg['docker'],'exec',node,'crictl','inspect',container]))['info'];netpath=next(x['path'] for x in info['runtimeSpec']['linux']['namespaces'] if x['type']=='network');netns='/proc/'+str(nodepid)+'/root'+netpath
 assert uid not in initial_pod_uids,'not a genuinely fresh runtime Pod; refuse pooled fixture authority'
 native_root=Path('/proc')/str(nodepid)/'root/proc'/str(info['pid'])/'root'
 ack_path=native_root/'tmp/poc-network-independent-receivers-ready'
 result_path=native_root/'tmp/poc-network-independent-result.json'
 assert not ack_path.exists() and not result_path.exists(),'ambiguous prior fixture files'
 assert len(live)==1,'one new public task required'
 fixture_identity={'task_uid':live[0]['metadata']['uid'],'session_uid':live[0]['status']['execution'].get('runtimeSessionUID'),'pod_uid':uid,'container_id':container,'token':secrets.token_hex(24),'scenario':cfg['scenario']}
 result.update(pod_name=podname,pod_uid=uid,container_id=container,fixture_identity=fixture_identity,fresh_container_verified=True,fixture_files_absent_before_ack=True)

 child('receivers',[cfg['nsenter'],'--net='+netns,'--',cfg['fixture_python'],str(fixture_inputs/'orka-same-policy-fixture.py'),'receivers',str(out)])
 until(lambda:(out/'receivers-ready').exists(),15)
 # Real equivalent unrestricted control to each actual receiver; separate log.
 control="import socket;[(lambda s:(s.connect(('169.254.17.1',p)),s.sendall(b'unrestricted-control'),s.close()))(socket.socket()) for p in [28296,28293]]"
 call([cfg['nsenter'],'--net='+netns,'--',cfg['fixture_python'],'-c',control])

 def receiver_rows():
  return [json.loads(line) for line in (out/'receiver.jsonl').read_text().splitlines()] if (out/'receiver.jsonl').exists() else []
 until(lambda:all(any(x.get('port')==port and x.get('data')=='unrestricted-control' for x in receiver_rows()) for port in [28296,28293]),10)
 result['controls_observed_before_ack']=receiver_rows()
 # Create only on verified fresh container, never overwrite ambiguous prior files.
 with ack_path.open('x') as f:f.write(json.dumps(fixture_identity))
 ack_path.chmod(0o444)

 q.wait(timeout=220)

 result['kmx_exit_code']=q.returncode
 tasks=json.loads(kub('get','tasks','-n',ns,'-o','json'));(out/'tasks.json').write_text(json.dumps(tasks,indent=2));new=[x for x in tasks['items'] if x['metadata']['uid'] not in old];assert len(new)==1;result['task_name']=new[0]['metadata']['name'];result['task_uid']=new[0]['metadata']['uid'];result['task_phase']=new[0].get('status',{}).get('phase');result['task_execution']=new[0].get('status',{}).get('execution')
 for resource in ['pods','runtimepools','runtimesessioncontrols']:(out/(resource+'.json')).write_text(kub('get',resource,'-A','-o','json')+'\n')
 (out/'supervisor.log').write_text(kub('logs',podname,'-n',cfg['runtime_namespace'],'--tail=160',check=False)+'\n')
 info=json.loads(call([cfg['docker'],'exec',node,'crictl','inspect',container]))['info']
 native_path=Path('/proc')/str(nodepid)/'root/proc'/str(info['pid'])/'root/tmp/poc-network-independent-result.json'
 native=native_path.read_text()
 (out/'native-probe.json').write_text(native)
 observation=json.loads(native)
 result['native_readback']={'path':str(native_path),'container_id':container,'pod_uid':uid,'node_pid':info['pid']}
 assert observation['ack']==fixture_identity,'stale/wrong Task observation'
 assert observation['uid']>0 and observation['pid']>0
 result['native_observation']=observation
 arrivals=receiver_rows()
 result['receiver_observations']=arrivals
 payload=[x for x in arrivals if x.get('data')=='orka-network-independent-probe' and x.get('port')==28296]

 if cfg['scenario']=='empty':
  assert observation['connected'] is False and observation['write_completed'] is False and observation['error'] in ['EPERM','EACCES'] and not payload
 else:assert observation['connected'] is True and observation['write_completed'] is True and observation['error'] is None and payload
 result['effect_success']=True
 result['inference_success']=False
finally:
 # No fixture file deletion: preserved inside exact owning container for readback.
 # Stop exact manager first; daemon remains until restrictions are known absent.
 for name,p in reversed(children):
  if name=='guardd':continue
  if p.poll() is None:p.terminate()
  try:p.wait(timeout=15)
  except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
  result[name+'_exit_code']=p.returncode
 if (out/'peer.db').exists():
  with sqlite3.connect('file:'+str(out/'peer.db')+'?mode=ro',uri=True) as db:result['bindings']=db.execute('SELECT operation,phase FROM bindings').fetchall()
 result['pins_remaining']=[str(p.relative_to(conf['pins'])) for p in Path(conf['pins']).rglob('*')]
 safe=not result['pins_remaining'] and all(row[1]=='RETIRED' for row in result.get('bindings',[]))
 result['safe_peer_stop']=safe
 for name,p in children:
  if name!='guardd':continue
  if safe:
   if p.poll() is None:p.terminate()
   try:p.wait(timeout=15)
   except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
   result['guardd_exit_code']=p.returncode
  else:result['guardd_pid_retained']=p.pid
 result['cleanup_qualified']=safe and result.get('manager_exit_code')==0 and result.get('guardd_exit_code')==0
 result['success']=result.get('effect_success',False) and result['cleanup_qualified']
 for log in logs:log.close()
 (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2));sys.exit(0 if result['success'] else 1)
