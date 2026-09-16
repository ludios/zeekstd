#!/usr/bin/env python3
import pathlib, subprocess
import run_matrix as m
m.RECORDS=pathlib.Path('logs/extended.jsonl'); m.RECORDS.write_text('')
for level in [-2147483648,-131072,-1,23,100,2147483647]:
    m.case(f'extreme-level-{level}','data/mixed.bin',[f'--compression-level={level}','-s','4096'])
for level in [19,20,22]:
    m.case(f'large-level-{level}','data/window-input.bin',[f'--compression-level={level}','-s','4294967295'])
# A large base exercises both the CLI's automatically selected window and stock
# zstd's dictionary-size limit. It is regular data, not a crafted compressed file.
base='data/prefix-129m.bin'
chunk=pathlib.Path('data/random.bin').read_bytes()
with open(base,'wb') as f:
    left=129<<20
    while left:
        b=chunk[:min(left,len(chunk))]; f.write(b); left-=len(b)
name='large-prefix'
archive=m.case(name,'data/patched.bin',['--patch-from',base,'-s','131072'],reference=False)
expected=m.sha('data/patched.bin')
for role,flags in [('dict',['-D',base]),('dict-memory',['--memory=512MB','-D',base]),('patch',['--patch-from='+base])]:
    m.run(name,role,['zstd','-d','-c',*flags,archive],expected=expected)
# Generic fallback for multi-frame prefixes: discover real frame boundaries
# with libzstd, then invoke stock zstd --patch-from independently for each frame.
rows=[tuple(map(int,line.split()[:2])) for line in subprocess.check_output([m.PROBE,'scan',archive],text=True).splitlines()]
data=pathlib.Path(archive).read_bytes()
parts=[]
for i,(off,n) in enumerate(rows):
    if data[off:off+4] != bytes.fromhex('28b52ffd'): continue
    frame=f'results/large-prefix-frame-{i}.zst'; out=f'results/large-prefix-frame-{i}.out'
    pathlib.Path(frame).write_bytes(data[off:off+n])
    # Each decompressed frame is compared to the corresponding source slice.
    original=f'data/large-prefix-frame-{i}.bin'
    pathlib.Path(original).write_bytes(pathlib.Path('data/patched.bin').read_bytes()[i*131072:(i+1)*131072])
    m.run(name,f'frame-{i}',['zstd','-d','-c','--patch-from='+base,frame],expected=m.sha(original))
print('DONE extended')
