#!/usr/bin/env python3
"""Build exact selected native qualification companions from clean reconstruction.
No fetch, publication, module edits or hidden source overlays. Go may populate its
normal module cache according to committed go.sum; supply a prepopulated cache for
offline builds. This builds fixtures, NOT a production deployment or runtime PASS.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--sources',type=Path,required=True)
p.add_argument('--out',type=Path,required=True)
p.add_argument('--go',type=Path,required=True)
p.add_argument('--manifest',type=Path,default=HERE.parents[1]/'docs/poc/sources.json')
p.add_argument('--gomodcache',type=Path)
p.add_argument('--gocache',type=Path)
a=p.parse_args()
a.sources,a.out,a.go=(x.resolve() for x in (a.sources,a.out,a.go))
if a.out.exists():raise SystemExit('requires NEW output; never overwrite prior logs or executables')
rows={r['repository']:r for r in json.loads(a.manifest.read_text())['rows']}
def git(source,*args):
 return subprocess.check_output(['git','-c','safe.directory='+str(source),'-C',str(source),*args],text=True).strip()
for name in rows:
 source=a.sources/name
 if git(source,'write-tree')!=rows[name]['tree'] or git(source,'diff','--name-only') or git(source,'ls-files','--others','--exclude-standard'):
  raise SystemExit('requires exact clean reconstructed source: '+name)
version=subprocess.check_output([str(a.go),'version'],text=True).strip()
if ' go1.27.2 ' not in version:raise SystemExit('qualification pin requires Go 1.27.2: '+version)
a.out.mkdir(mode=0o700,parents=True,exist_ok=False)
# Workspace contains EXACT selected unpublished companions, kept outside source.
workspaces={
 'kagent':dict(use=['kagent/go'],replace={'github.com/agent-substrate/substrate':'substrate-kagent'}),
 'sessions':dict(use=['sessions','sessions/integrations/substrate'],replace={'github.com/agent-substrate/substrate':'substrate-sessions'}),
 'kaimahi':dict(use=['kaimahi','sessions/integrations/substrate','suite'],replace={'github.com/agent-substrate/substrate':'substrate-sessions','github.com/agent-primitives/sessions':'sessions'}),
}
for name,w in workspaces.items():
 text='go 1.27.0\nuse (\n'+''.join(' '+json.dumps(str((a.sources/v).resolve()))+'\n' for v in w['use'])+')\n'
 text+=''.join('replace '+k+' => '+json.dumps(str((a.sources/v).resolve()))+'\n' for k,v in w['replace'].items())
 (a.out/(name+'.work')).write_text(text)
items=[]
for fork in ['kagent','sessions']:
 repo='substrate-'+fork
 for name,pkg in [('microvm','./cmd/ateom-microvm'),('atelet','./cmd/atelet'),('control','./cmd/ateapi/internal/controlapi'),('router','./cmd/atenet/internal/router')]:
  items.append(dict(id=fork+'-'+name,repository=repo,cwd=repo,package=pkg,test=True,workspace=None))
items += [
 dict(id='sessions-harnessnode',repository='sessions',cwd='sessions',package='./cmd/harnessnode',test=False,workspace='sessions',static=True),
 dict(id='sessions-daemon',repository='sessions',cwd='sessions/integrations/substrate',package='./cmd/agentsessions-substrate',test=False,workspace='sessions'),
 dict(id='kaimahi-public-tests',repository='kaimahi',cwd='kaimahi',package='./internal/kmx/app',test=True,workspace='kaimahi',tags=['nativeintegration']),
 dict(id='kaimahi-cli',repository='kaimahi',cwd='kaimahi',package='./cmd/kmx',test=False,workspace='kaimahi'),
 dict(id='kagent-codex',repository='kagent',cwd='kagent/go',package='./harness/codex/cmd',test=False,workspace='kagent',static=True),
 dict(id='kagent-app',repository='kagent',cwd='kagent/go',package='./core/pkg/app',test=True,workspace='kagent'),
 dict(id='kagent-a2a',repository='kagent',cwd='kagent/go',package='./core/internal/a2agateway',test=True,workspace='kagent'),
]
env=dict(os.environ,GOTOOLCHAIN='local',GOMAXPROCS='6')
if a.gomodcache:env['GOMODCACHE']=str(a.gomodcache.resolve())
if a.gocache:env['GOCACHE']=str(a.gocache.resolve())
result=dict(classification='exact reconstructed source builds only; tests NOT RUN here',toolchain=version,rows=[])
def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(1<<20),b''):h.update(chunk)
 return h.hexdigest()
try:
 for item in items:
  binary=a.out/item['id']
  command=[str(a.go),'test','-c'] if item['test'] else [str(a.go),'build']
  command+=['-p','4','-trimpath','-o',str(binary)]
  if item.get('tags'):command+=['-tags',','.join(item['tags'])]
  command.append(item['package'])
  runenv=dict(env,GOWORK=str(a.out/(item['workspace']+'.work')) if item['workspace'] else 'off')
  if item.get('static'):runenv['CGO_ENABLED']='0'
  row=dict(item,command=command,tree=rows[item['repository']]['tree'],environment={k:runenv[k] for k in ['GOWORK','GOTOOLCHAIN','GOMAXPROCS']})
  with (a.out/(item['id']+'.build.log')).open('w') as log:
   completed=subprocess.run(command,cwd=a.sources/item['cwd'],env=runenv,stdout=log,stderr=subprocess.STDOUT,timeout=600)
  row['exit_code']=completed.returncode
  if binary.exists():
   row['sha256']=sha(binary)
   versioncmd=[str(a.go),'version','-m',str(binary)]
   row['go_build_info']=subprocess.check_output(versioncmd,text=True,timeout=15)
  row['source_clean_after']=git(a.sources/item['repository'],'write-tree')==row['tree'] and not git(a.sources/item['repository'],'diff','--name-only')
  result['rows'].append(row)
  (a.out/'build-manifest.json').write_text(json.dumps(result,indent=2)+'\n')
  print(item['id'],completed.returncode,flush=True)
  if completed.returncode or not row['source_clean_after']:raise RuntimeError('build failed; retained exact logs: '+item['id'])
finally:
 (a.out/'build-manifest.json').write_text(json.dumps(result,indent=2)+'\n')
