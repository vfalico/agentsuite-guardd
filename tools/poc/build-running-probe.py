#!/usr/bin/env python3
"""Locked public source preparation + two explicit TEST-only probe overlays.
No history paths, unpublished hidden changes, downloads beyond Go module policy,
or native execution. Output must be new. Build manifest is NOT acceptance.
"""
import argparse,hashlib,json,os,pathlib,subprocess,time
HERE=pathlib.Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--sources',type=pathlib.Path,required=True)
p.add_argument('--manifest',type=pathlib.Path,required=True)
p.add_argument('--out',type=pathlib.Path,required=True)
p.add_argument('--go',type=pathlib.Path,required=True)
p.add_argument('--module-cache',type=pathlib.Path,required=True)
p.add_argument('--build-cache',type=pathlib.Path,required=True)
p.add_argument('--prepare-only',action='store_true')
a=p.parse_args()
for key in ['sources','manifest','go','module_cache','build_cache']:setattr(a,key,getattr(a,key).resolve(strict=True))
a.out=a.out.resolve();a.out.mkdir(mode=0o700)
manifest=json.loads(a.manifest.read_text());rows={r['repository']:r for r in manifest['rows']}
def sha(p):
 with pathlib.Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def run(cmd,**kw):return subprocess.check_output([str(x) for x in cmd],stderr=subprocess.STDOUT,**kw).decode().strip()
def git(repo,*args):return run(['git','-C',repo,*args])
version=run([a.go,'version'])
if 'go1.27.2 ' not in version:raise SystemExit('requires qualified Go 1.27.2, got '+version)
for root in [a.out,a.build_cache,a.module_cache]:
 st=os.statvfs(root)
 if st.f_bavail*st.f_frsize<=5*1024**3 or st.f_favail<1024:raise SystemExit('headroom '+str(root))
overlays=HERE.parents[1]/'examples/poc/kagent/fixture-overlays'
fixture_pins=json.loads((overlays/'manifest.json').read_text())
allowed={'kagent':'go/core/pkg/app/native_app_test.go','substrate-kagent':'cmd/ateom-microvm/native_sessions_tools_linux_test.go'}
report={'classification':'clean source preparation and build only; native NOT RUN','toolchain':version,'manifest_sha256':sha(a.manifest),'source_overlays':[],'builds':[]}
try:
 for repo,path in allowed.items():
  source=a.sources/repo;row=rows[repo]
  if git(source,'write-tree')!=row['tree'] or git(source,'diff','--name-only'):raise RuntimeError('source not exact selected tree: '+repo)
  target=a.out/repo
  run(['git','clone','--no-checkout','--shared',source,target])
  git(target,'checkout','--detach',row['commit'])
  if git(target,'write-tree')!=row['tree']:raise RuntimeError('source commit/tree mismatch')
  overlay=overlays/(repo+'.patch');git(target,'apply','--check',overlay);git(target,'apply','--index',overlay)
  changed=git(target,'diff','--name-only',row['tree']).splitlines()
  if changed!=[path]:raise RuntimeError('undeclared overlay '+repr(changed))
  if (fixture_pins['overlays'][repo]['base_commit']!=row['commit'] or sha(overlay)!=fixture_pins['overlays'][repo]['patch_sha256'] or sha(target/path)!=fixture_pins['overlays'][repo]['result_sha256']):raise RuntimeError('published fixture integrity mismatch '+repo)
  report['source_overlays'].append({'repository':repo,'production_tree':row['tree'],'test_tree':git(target,'write-tree'),'overlay_sha256':sha(overlay),'changed_files':changed,'source_sha256':sha(target/path)})
 # Build final workload, not an obsolete first fixture/assertion revision.
 probe=a.out/'probe';probe.mkdir();(probe/'main.go').write_bytes((HERE/'network-independent-kagent.go').read_bytes())
 if sha(probe/'main.go')!=fixture_pins['workload_sha256']:raise RuntimeError('published workload integrity mismatch')
 (probe/'go.mod').write_text('module poc-network-independent-probe\n\ngo 1.27.0\n\nrequire github.com/kagent-dev/kagent/go v0.0.0\nreplace github.com/kagent-dev/kagent/go => '+json.dumps(str(a.out/'kagent/go'))+'\nreplace github.com/agent-substrate/substrate => '+json.dumps(str(a.out/'substrate-kagent'))+'\n')
 projects=[('network-independent-kagent',probe,'.',False),('kagent-app',a.out/'kagent/go','./core/pkg/app',True),('kagent-microvm',a.out/'substrate-kagent','./cmd/ateom-microvm',True)]
 for name,cwd,package,test in projects:
  work=a.out/(name+'.work');uses=[a.out/'kagent/go']
  if name=='network-independent-kagent':uses.insert(0,probe)
  if name=='kagent-microvm':uses=[a.out/'substrate-kagent']
  work.write_text('go 1.27.0\nuse (\n'+''.join(json.dumps(str(x))+'\n' for x in uses)+')\n'+('replace github.com/agent-substrate/substrate => '+json.dumps(str(a.out/'substrate-kagent'))+'\n' if name!='kagent-microvm' else ''))
  cmd=[a.go,'test','-c'] if test else [a.go,'build']
  cmd += ['-p','4','-trimpath','-o',a.out/name,package]
  row={'name':name,'command':[str(x) for x in cmd],'cwd':str(cwd),'workspace':str(work),'status':'NOT RUN' if a.prepare_only else 'building'}
  report['builds'].append(row)
  if a.prepare_only:continue
  env=dict(os.environ,GOTOOLCHAIN='local',GOWORK=str(work),GOMODCACHE=str(a.module_cache),GOCACHE=str(a.build_cache),GOTMPDIR=str(a.out),TMPDIR=str(a.out),GOPROXY='off',CGO_ENABLED='1' if test else '0')
  with (a.out/(name+'-build.log')).open('w') as log:
   q=subprocess.run([str(x) for x in cmd],cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=600)
  row.update(exit_code=q.returncode,status='built' if q.returncode==0 else 'FAILED')
  if q.returncode:raise RuntimeError(name+' build failed; inspect bounded log')
  row.update(sha256=sha(a.out/name),bytes=(a.out/name).stat().st_size)
 report['complete']=True
finally:
 (a.out/'build-probe.json').write_text(json.dumps(report,indent=2)+'\n')
