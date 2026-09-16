#!/usr/bin/env python3
import csv, hashlib, json, pathlib, re, collections
ROOT=pathlib.Path(__file__).resolve().parent.parent
stages=['cli','library','large','special','followups','extended','recovery','dependency-audit','corpus']
rows=[]
for stage in stages:
    rows.extend(dict(json.loads(line), stage=stage) for line in (ROOT/f'logs/{stage}.jsonl').read_text().splitlines())
columns=['stage','case','role','rc','bytes','sha256','expected_sha256','match','seconds','command','stderr']
with (ROOT/'results/commands.csv').open('w') as f:
    w=csv.DictWriter(f,fieldnames=columns,extrasaction='ignore'); w.writeheader(); w.writerows(rows)
encodes=[r for r in rows if r['role']=='encode']
archive_rows=[]
for e in encodes:
    related=[r for r in rows if r['case']==e['case']]
    z=next((r for r in related if r['role']=='zstd'),{})
    ref=next((r for r in related if r['role']=='reference'),{})
    archive_rows.append(dict(case=e['case'],stage=e['stage'],encode_rc=e['rc'],encode_command=e['command'],expected_sha256=z.get('expected_sha256'),zstd_rc=z.get('rc'),zstd_hash_match=z.get('match'),reference_rc=ref.get('rc'),reference_hash_match=ref.get('match'),reference_details=ref.get('stderr'),successful_recovery_roles=';'.join(r['role'] for r in related if r['expected_sha256'] and r['rc']==0 and r['match'])))
    # Confirm the checksum configuration in every original reference-accepted archive.
    if ref.get('rc')==0:
        n,c=map(int,re.search(r'frames=(\d+).*checksum_frames=(\d+)',ref['stderr']).groups())
        check=('--no-checksum' not in e['argv']) if e['argv'][0].endswith('/zeekstd') else ('checksum=1' in e['argv'])
        assert c==(n if check else 0), (e['case'],n,c,check)
with (ROOT/'results/archives.csv').open('w') as f:
    w=csv.DictWriter(f,fieldnames=list(archive_rows[0])); w.writeheader(); w.writerows(archive_rows)
stats={stage:dict(commands=sum(r['stage']==stage for r in rows),writer_attempts=sum(r['stage']==stage for r in encodes),writes_ok=sum(r['stage']==stage and r['rc']==0 for r in encodes),hash_checks=sum(r['stage']==stage and r['expected_sha256'] is not None for r in rows),hash_pass=sum(r['stage']==stage and r['expected_sha256'] is not None and r['rc']==0 and r['match'] for r in rows)) for stage in stages}
(ROOT/'results/summary.json').write_text(json.dumps(stats,indent=2)+'\n')
failures=[r for r in rows if r['rc']!=0 or r['expected_sha256'] is not None and not r['match']]
with (ROOT/'results/failure-transcripts.md').open('w') as f:
    f.write('# Complete non-passing command transcripts\n\nAll paths are relative to the workspace root. Each decoding command had stdout streamed into SHA-256, rather than discarded; stdout hashes and byte counts below are exact. These include expected dependency/format/tool limits, controls, and intentional path collisions. Classification and remedies are in report.md.\n\n')
    for i,r in enumerate(failures,1):
        f.write(f'### {i}. {r["case"]} / {r["role"]}\n\n')
        producer=next((e for e in encodes if e['case']==r['case']),None)
        if producer and r['role']!='encode': f.write('Producer:\n\n```sh\n'+producer['command']+'\n```\n\n')
        f.write('Command under test:\n\n```sh\n'+r['command']+'\n```\n\n')
        f.write(f'Exit: {r["rc"]}; stdout bytes: {r["bytes"]}; SHA-256: `{r["sha256"]}`.\n\n')
        if r['expected_sha256']: f.write(f'Expected SHA-256: `{r["expected_sha256"]}`.\n\n')
        f.write('Stderr:\n\n```text\n'+(r['stderr'] or '(empty)\n')+'```\n\n')
print(json.dumps(stats,indent=2))
print('Total writer attempts:',len(encodes),'successful:',sum(r['rc']==0 for r in encodes))
print('Total hash checks:',sum(r['expected_sha256'] is not None for r in rows),'passing:',sum(r['expected_sha256'] is not None and r['rc']==0 and bool(r['match']) for r in rows))
print('Non-passing command transcripts:',len(failures))
