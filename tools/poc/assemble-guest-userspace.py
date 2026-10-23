#!/usr/bin/env python3
"""Build a disposable initramfs from explicit host userspace for feasibility only.
No installed host or Kata assets are modified. Package versions are recorded.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

p=argparse.ArgumentParser()
p.add_argument('--bpftool',type=Path,required=True,help='Actual compatible bpftool ELF, not a shell wrapper')
p.add_argument('--kernel-work',type=Path,required=True)
p.add_argument('--guardd-source',type=Path,required=True)
p.add_argument('--probe',type=Path,required=True)
p.add_argument('--out',type=Path,required=True)
a=p.parse_args()
a.out.mkdir(mode=0o700,parents=True,exist_ok=False)
root=a.out/'root';root.mkdir()
for name in ('bin','sbin','dev','proc','sys','tmp','state','run','usr/bin','usr/sbin','usr/lib','lib','lib64'):
    (root/name).mkdir(parents=True,exist_ok=True)

def copy_file(source):
    source=Path(source)
    dest=root/str(source).lstrip('/')
    dest.parent.mkdir(parents=True,exist_ok=True)
    if not dest.exists():shutil.copy2(source.resolve(),dest)

def binary(source):
    copy_file(source)
    result=subprocess.run(['ldd',str(source)],capture_output=True,text=True)
    for line in result.stdout.splitlines():
        tokens=line.replace('=>',' ').split()
        for token in tokens:
            if token.startswith('/') and Path(token).is_file():copy_file(token)

for b in ('/usr/bin/busybox','/usr/bin/python3.12',str(a.bpftool.resolve(strict=True)),'/usr/lib/x86_64-linux-gnu/libbpf.so.1'):
    binary(b)
shutil.copy2(str(a.bpftool.resolve(strict=True)),root/'usr/sbin/bpftool')
shutil.copytree('/usr/lib/python3.12',root/'usr/lib/python3.12',dirs_exist_ok=True,ignore=shutil.ignore_patterns('__pycache__','test','tests'))
for so in Path('/usr/lib/python3.12/lib-dynload').glob('*.so'):binary(so)
shutil.copytree(a.guardd_source/'src/agentsuite_guardd',root/'guardd/agentsuite_guardd',ignore=shutil.ignore_patterns('__pycache__'))
shutil.copy2(a.probe,root/'probe.py')
with (a.out/'vmlinux.h').open('w') as f:
    subprocess.run(['bpftool','btf','dump','file',str(a.kernel_work/'vmlinux'),'format','c'],stdout=f,check=True)
subprocess.run(['clang','-O2','-g','-target','bpf','-D__TARGET_ARCH_x86','-I'+str(a.out),'-I/usr/include','-c',str(a.guardd_source/'gadget/network.bpf.c'),'-o',str(root/'network.bpf.o')],check=True)
init='''#!/usr/bin/busybox sh
/usr/bin/busybox --install -s /bin
mount -t devtmpfs devtmpfs /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t securityfs securityfs /sys/kernel/security
mount -t cgroup2 cgroup2 /sys/fs/cgroup
mount -t bpf bpf /sys/fs/bpf
ip link set lo up
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PYTHONPATH=/guardd
/usr/bin/python3.12 /probe.py
rc=$?
echo POC_GUEST_PROBE_EXIT=$rc
sync
poweroff -f
'''
(root/'init').write_text(init);(root/'init').chmod(0o755)
with (a.out/'initramfs.cpio.gz').open('wb') as out:
    subprocess.run(['bash','-o','pipefail','-c','find . -print0 | cpio --null -o --format=newc --owner=0:0 2>../cpio.log | gzip -1'],cwd=root,stdout=out,check=True)
packages=subprocess.check_output(['dpkg-query','-W','-f=${Package} ${Version}\n','python3.12','libbpf1','bpftool','busybox-static','clang','libc6'],text=True)
(a.out/'userspace-packages.txt').write_text(packages)
print(json.dumps(dict(initramfs=str(a.out/'initramfs.cpio.gz'),bytes=(a.out/'initramfs.cpio.gz').stat().st_size)))
