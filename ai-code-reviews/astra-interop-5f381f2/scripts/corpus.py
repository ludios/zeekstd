#!/usr/bin/env python3
import pathlib
import run_matrix as m
m.RECORDS=pathlib.Path('logs/corpus.jsonl'); m.RECORDS.write_text('')
for policy,level,size in [('uncompressed',3,'2M'),('compressed',3,'64K'),('uncompressed',19,'2M'),('uncompressed',22,'1G')]:
    m.case(f'dickens-{policy[0]}-l{level}-s{size}','zeekstd/assets/dickens.txt',['--frame-size-policy',policy,f'--compression-level={level}','-s',size])
print('DONE corpus')
