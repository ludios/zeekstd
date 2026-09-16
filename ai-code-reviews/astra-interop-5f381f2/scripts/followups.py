#!/usr/bin/env python3
"""Focused controls, layouts, and ordinary-data edge cases found during testing."""
import pathlib, struct, subprocess, random, json, shutil
import run_matrix as m
m.STAGE='followups'
m.RECORDS=pathlib.Path('logs/followups.jsonl')
m.RECORDS.write_text('')

# A stock-zstd control demonstrates the lifetime of --patch-from over frames.
base='data/prefix.bin'
data=pathlib.Path('data/patched.bin').read_bytes()
for i,b in enumerate([data[:131072],data[131072:262144]]):
    src=f'data/control{i}.bin'; pathlib.Path(src).write_bytes(b)
    m.run(f'control{i}','stock-encode',['zstd','-f','--patch-from='+base,src,'-o',f'results/control{i}.zst'])
    m.run(f'control{i}','stock-patch',['zstd','-d','-c','--patch-from='+base,f'results/control{i}.zst'],expected=m.sha(src))
pathlib.Path('data/control-concat.bin').write_bytes(data[:262144])
pathlib.Path('results/control-concat.zst').write_bytes(b''.join(pathlib.Path(f'results/control{i}.zst').read_bytes() for i in range(2)))
for role,flags in [('patch',['--patch-from='+base]),('dict',['-D',base])]:
    m.run('control-concat',role,['zstd','-d','-c',*flags,'results/control-concat.zst'],expected=m.sha('data/control-concat.bin'))

# Independently parse all alternate layouts; convert ONLY the metadata to Foot
# and ask the reference decoder to validate data frames and recover the bytes.
for api in ['raw','writer']:
    for fmt in ['head','foot']:
        for side in [0,1]:
            for kind in ['empty','mixed']:
                name=f'layout-{api}-{fmt}-side{side}-{kind}'
                if fmt=='foot' and not side: continue # Already reference-tested.
                archive=f'results/{name}.zst'
                frames=subprocess.check_output([m.PROBE,'scan',archive],text=True)
                rows=[(int(o),int(n),magic) for o,n,magic in map(str.split,frames.splitlines())]
                raw=pathlib.Path(archive).read_bytes()
                if side:
                    tab=pathlib.Path(archive+'.table').read_bytes(); body=raw
                else:
                    assert rows[-1][2]=='5e2a4d18'
                    off,n,magic=rows.pop(); body=raw[:off]; tab=raw[off:]
                assert all(magic=='28b52ffd' for _,_,magic in rows)
                magic,size=struct.unpack('<II',tab[:8]); assert magic==0x184d2a5e and size==len(tab)-8
                if fmt=='head': integ=tab[8:17]; entries=tab[17:]
                else: integ=tab[-9:]; entries=tab[8:-9]
                count,desc,magic=struct.unpack('<IBI',integ)
                assert count==len(rows) and desc==0 and magic==0x8f92eab1
                sizes=list(struct.iter_unpack('<II',entries)); assert len(sizes)==count
                assert [c for c,d in sizes]==[n for o,n,magic in rows]
                assert sum(d for c,d in sizes)==pathlib.Path(f'data/{kind}.bin').stat().st_size
                converted=f'results/{name}-foot.zst'
                pathlib.Path(converted).write_bytes(body+tab[:8]+entries+integ)
                m.run(name,'converted-reference',[m.PROBE,'oracle',converted,f'data/{kind}.bin'],expected=m.sha(f'data/{kind}.bin'))

# Cover every positive library/CLI level, including ultra levels not advertised by help.
for level in range(1,23):
    m.case(f'every-level-{level}','data/mixed.bin',[f'--compression-level={level}','-s','4096'])
for checksum in [0,1]:
    for size in [1,13,127]:
        m.case(f'pending-flush-{size}-c{checksum}','data/random.bin',
               ['api=raw','frame=4096','in=4093',f'out={size}','end=3','end_flush=1',f'checksum={checksum}'],api='library')

# A trained, ID-bearing dictionary (not only a raw prefix).
train=pathlib.Path('data/training'); train.mkdir(exist_ok=True)
r=random.Random(99112)
for i in range(100):
    (train/f'{i:03}.txt').write_bytes((f'record {i}: zeekstd archival dictionary sample\n'.encode()+r.randbytes(50))*20)
m.run('trained-dict','train',['zstd','--train','--maxdict=4096','-f',*[str(p) for p in sorted(train.iterdir())],'-o','data/trained.dict'])
src='data/dictionary-input.bin'; pathlib.Path(src).write_bytes(b''.join(p.read_bytes() for p in sorted(train.iterdir())[::3]))
for api in ['raw','writer']:
    name=f'trained-{api}'
    archive=m.case(name,src,[f'api={api}','dict=data/trained.dict','frame=4096','checksum=1'],api='library',reference=False)
    m.run(name,'with-dict',['zstd','-d','-c','-D','data/trained.dict',archive],expected=m.sha(src))

# Tools which search rather than reconstruct: compare the search output itself.
src='data/text.bin'; archive='results/cli-text-u-s127-l3-c1.zst'
expected=pathlib.Path('results/grep-expected.txt')
with expected.open('wb') as f: subprocess.run(['grep','-a','archival',src],stdout=f,check=True)
m.run('grep','zstdgrep',['zstdgrep','-a','archival',archive],expected=m.sha(expected))

# Prefix roundtrips through zeekstd are secondary: standard zstd -D is the recovery oracle.
for policy in ['u','c']:
    name=f'patch-{policy}-mmap-prefix-side0-c1'
    m.run(name,'zeekstd-patch',[m.ZEEK,'decompress','-q','-c','--patch-apply',base,f'results/{name}.zst'],expected=m.sha('data/patched.bin'))

# Writer path collisions noticed in source. Isolated copies; never original test inputs.
pathlib.Path('results/collision-input.bin').write_bytes(data[:4096])
m.run('collision-input','encode',[m.ZEEK,'compress','-q','-f','results/collision-input.bin','-o','results/collision-input.bin'])
pathlib.Path('data/collision-expected.bin').write_bytes(data[:4096])
m.run('collision-input','zstd',['zstd','-d','-c','results/collision-input.bin'],expected=m.sha('data/collision-expected.bin'))
m.run('collision-sidecar','encode',[m.ZEEK,'compress','-q','-f','data/mixed.bin','-o','results/collision-sidecar.zst','--seek-table-file','results/collision-sidecar.zst'])
m.run('collision-sidecar','zstd',['zstd','-d','-c','results/collision-sidecar.zst'],expected=m.sha('data/mixed.bin'))
print('DONE followups')
