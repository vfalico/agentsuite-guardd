#!/usr/bin/env python3
"""Append tiny explicit TEST workload layer to pinned existing local OCI image.
No product binary, supervisor, helper, gate, adapter or Codex bytes change.
Existing base blobs streamed from task-owned node into RAM archive; never publish.
"""
import argparse,hashlib,io,json,os,pathlib,subprocess,tarfile,time
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--node',required=True);p.add_argument('--base',required=True)
p.add_argument('--probe',type=pathlib.Path,required=True);p.add_argument('--out',type=pathlib.Path,required=True)
a=p.parse_args();a.out.mkdir(mode=0o700)
if not a.base.startswith('sha256:'):raise SystemExit('exact base digest required')
def content(digest):return subprocess.check_output(['docker','exec',a.node,'ctr','-n','k8s.io','content','get',digest])
def encoded(value):return json.dumps(value,separators=(',',':'),sort_keys=True).encode()
def descriptor(raw,media):return {'mediaType':media,'digest':'sha256:'+hashlib.sha256(raw).hexdigest(),'size':len(raw)}
manifest_raw=content(a.base);assert 'sha256:'+hashlib.sha256(manifest_raw).hexdigest()==a.base
manifest=json.loads(manifest_raw);config=json.loads(content(manifest['config']['digest']))
probe=a.probe.read_bytes()
# Only the normal ACP provider entrypoint executes the network-independent probe.
wrapper=b'#!/bin/sh\nif [ "$#" = 1 ] && [ "$1" = /opt/codex-acp/dist/index.js ]; then\n /usr/local/bin/node /opt/poc-network-independent.js || exit $?\nfi\nexec /usr/local/bin/node "$@"\n'

layerpath=a.out/'layer.tar'
with tarfile.open(layerpath,'w',format=tarfile.USTAR_FORMAT) as tar:
 for name,raw,mode in [('usr/bin/node',wrapper,0o755),('opt/poc-network-independent.js',probe,0o644)]:
  info=tarfile.TarInfo(name);info.size=len(raw);info.mode=mode;info.uid=info.gid=0;info.mtime=0;tar.addfile(info,io.BytesIO(raw))
layer=layerpath.read_bytes();ld=descriptor(layer,'application/vnd.oci.image.layer.v1.tar');manifest['layers'].append(ld)
config['rootfs']['diff_ids'].append(ld['digest']);config.setdefault('history',[]).append({'created_by':'POC TEST-only network-independent provider entrypoint probe; no inference success'})
config_raw=encoded(config);cd=descriptor(config_raw,'application/vnd.oci.image.config.v1+json');manifest['config']=cd
new_raw=encoded(manifest);md=descriptor(new_raw,'application/vnd.oci.image.manifest.v1+json');md['annotations']={'org.opencontainers.image.ref.name':'docker.io/library/poc-orka-network-independent:local'}
archive=a.out/'image.tar';index=encoded({'schemaVersion':2,'manifests':[md]})
with tarfile.open(archive,'w') as tar:
 def add(name,raw):
  info=tarfile.TarInfo(name);info.size=len(raw);info.mode=0o644;tar.addfile(info,io.BytesIO(raw))
 add('oci-layout',b'{"imageLayoutVersion":"1.0.0"}');add('index.json',index)
 originals=json.loads(manifest_raw)['layers']+[json.loads(manifest_raw)['config']]
 for row in originals:
  raw=content(row['digest']);assert len(raw)==row['size'];assert 'sha256:'+hashlib.sha256(raw).hexdigest()==row['digest'];add('blobs/sha256/'+row['digest'][7:],raw)
 for raw,d in [(layer,ld),(config_raw,cd),(new_raw,md)]:add('blobs/sha256/'+d['digest'][7:],raw)
(a.out/'receipt.json').write_text(json.dumps({'classification':'local TEST workload image, no production image change/publication','base_manifest':a.base,'image_manifest':md['digest'],'probe_sha256':hashlib.sha256(a.probe.read_bytes()).hexdigest(),'layer':ld,'base_layers_unchanged':True,'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest()},indent=2)+'\n')
print(md['digest'])
