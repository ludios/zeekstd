#!/usr/bin/env python3
import pathlib
import run_matrix as m
m.RECORDS=pathlib.Path('logs/recovery.jsonl'); m.RECORDS.write_text('')
src='data/patched.bin'; expected=m.sha(src)
m.run('large-prefix','patch-memory',['zstd','-d','-c','--memory=256MB','--patch-from=data/prefix-129m.bin','results/large-prefix.zst'],expected=expected)
for name,base in [('large-prefix','data/prefix-129m.bin'),('patch-u-mmap-prefix-side0-c1','data/prefix.bin')]:
    m.run(name,'python-frame-recovery',['python3','scripts/recover_patch.py',f'results/{name}.zst',base],expected=expected)
# Successful individual-frame repairs supplement the initially failed defaults.
for i in range(17):
    m.run('large-prefix',f'frame-memory-{i}', ['zstd','-d','-c','--memory=256MB','--patch-from=data/prefix-129m.bin',f'results/large-prefix-frame-{i}.zst'],expected=m.sha(f'data/large-prefix-frame-{i}.bin'))
print('DONE recovery')
