#!/usr/bin/env python3
"""Independently audit every dependency-bearing archive's table and each frame."""
import pathlib, json, struct, subprocess, tempfile
import run_matrix as m
m.RECORDS=pathlib.Path('logs/dependency-audit.jsonl'); m.RECORDS.write_text('')
records=[json.loads(s) for stage in ['special','followups','extended'] for s in pathlib.Path(f'logs/{stage}.jsonl').read_text().splitlines()]
for e in records:
    if e['role']!='encode' or e['rc'] or not e['case'].startswith(('patch-','dependency-','trained-','large-prefix')): continue
    name=e['case']; archive=f'results/{name}.zst'
    if name.startswith('trained-'): original='data/dictionary-input.bin'; base='data/trained.dict'
    else: original='data/patched.bin'; base='data/prefix-129m.bin' if name=='large-prefix' else 'data/prefix.bin'
    data=pathlib.Path(archive).read_bytes()
    scanned=[(int(o),int(n),magic) for o,n,magic in map(str.split,subprocess.check_output([m.PROBE,'scan',archive],text=True).splitlines())]
    side=pathlib.Path(archive+'.table')
    if side.exists():
        table=side.read_bytes(); integ=table[8:17]; entries=table[17:]; body=data
    else:
        off,n,magic=scanned.pop(); assert magic=='5e2a4d18'; table=data[off:]; body=data[:off]
        integ=table[-9:]; entries=table[8:-9]
    magic,size=struct.unpack('<II',table[:8]); assert magic==0x184d2a5e and size==len(table)-8
    count,desc,magic=struct.unpack('<IBI',integ); assert magic==0x8f92eab1 and desc==0 and count==len(scanned)
    sizes=list(struct.iter_unpack('<II',entries)); assert len(sizes)==count
    assert [c for c,d in sizes]==[n for o,n,magic in scanned]
    assert sum(c for c,d in sizes)==len(body)
    source=pathlib.Path(original).read_bytes(); assert sum(d for c,d in sizes)==len(source)
    co=do=0
    # Retain tiny individual frames and expected slices, so every command is replayable.
    frame_dir=pathlib.Path('results/dependency-frames')/name; frame_dir.mkdir(parents=True,exist_ok=True)
    for i,(c,d) in enumerate(sizes):
        frame=frame_dir/f'{i}.zst'; expected=frame_dir/f'{i}.original'
        frame.write_bytes(body[co:co+c]); expected.write_bytes(source[do:do+d])
        flags=['--memory=256MB','--patch-from='+base] if name=='large-prefix' else ['-D',base]
        r=m.run(name,f'frame-audit-{i}',['zstd','-d','-c',*flags,str(frame)],expected=m.sha(expected))
        assert r['rc']==0 and r['match']
        co+=c; do+=d
    print(f'TABLE_AND_FRAMES_OK {name} frames={count} compressed_data={co} decompressed={do}',flush=True)
