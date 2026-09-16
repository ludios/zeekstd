#!/usr/bin/env python3
"""Run from workspace root. Deterministic, no network; retains archives and logs.
Each command records argv, stdin, exit status, stderr, output length and SHA-256.
"""
import concurrent.futures as cf
import hashlib, itertools, json, os, pathlib, random, shlex, subprocess, sys, threading, time

ROOT = pathlib.Path(__file__).resolve().parent.parent
os.chdir(ROOT)
ZEEK = 'zeekstd/target/release/zeekstd'
PROBE = 'zeekstd/target/release/examples/interop_probe'
LOCK = threading.Lock()
for d in ['data', 'results', 'logs']: pathlib.Path(d).mkdir(exist_ok=True)
STAGE = sys.argv[1] if len(sys.argv) > 1 else 'cli'
RECORDS = pathlib.Path('logs') / (STAGE + '.jsonl')

def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while b := f.read(4 << 20): h.update(b)
    return h.hexdigest()

def run(case, role, argv, stdin=None, output=None, expected=None):
    start = time.monotonic()
    logfile = pathlib.Path('logs') / f'{case}.{role}.stderr'
    with open(logfile, 'wb') as err:
        inp = open(stdin, 'rb') if stdin else subprocess.DEVNULL
        out = open(output, 'wb') if output else subprocess.PIPE
        p = subprocess.Popen([str(x) for x in argv], stdin=inp, stdout=out, stderr=err)
        h = hashlib.sha256(); size = 0
        if not output:
            while b := p.stdout.read(4 << 20): h.update(b); size += len(b)
        rc = p.wait()
        if stdin: inp.close()
        if output: out.close()
    record = dict(case=case, role=role, argv=[str(x) for x in argv], stdin=stdin,
                  stdout_file=output, rc=rc, seconds=round(time.monotonic()-start, 3),
                  sha256=h.hexdigest() if not output else None, bytes=size if not output else None,
                  expected_sha256=expected, match=h.hexdigest() == expected if expected else None,
                  stderr=logfile.read_text(errors='replace'))
    record['command'] = shlex.join(record['argv']) + (f' < {shlex.quote(stdin)}' if stdin else '') + (f' > {shlex.quote(output)}' if output else '')
    with LOCK:
        with RECORDS.open('a') as f: f.write(json.dumps(record)+'\n')
        if rc or expected and not record['match']:
            print(f'NONPASS {case} {role} rc={rc} match={record["match"]} {record["stderr"][:160]!r}', flush=True)
    return record

def inputs():
    n = 262161
    r = random.Random(738149)
    text = (b'zeekstd archival interoperability: line 0123456789 abcdef\n' * n)[:n]
    dense = bytes(range(256)) * (n//256+1)
    noise = r.randbytes(n)
    mixed = (text[:65536] + noise[:65536] + bytes(65536) + dense[:65536] + b'end-of-input-12345')[:n]
    for name, b in [('text',text), ('dense',dense[:n]), ('random',noise), ('mixed',mixed), ('empty',b''), ('one',b'\x00')]:
        pathlib.Path(f'data/{name}.bin').write_bytes(b)
    pathlib.Path('data/prefix.bin').write_bytes(noise * 16)
    pathlib.Path('data/patched.bin').write_bytes(noise*4 + b'PATCH NEW CONTENT' + noise*4)
    for n in sorted(set([0,1,2,126,127,128,255,256,257,4095,4096,4097,131071,131072,131073,2097151,2097152,2097153,4194304,4194305])):
        pathlib.Path(f'data/n{n}.bin').write_bytes((noise * (n//len(noise)+1))[:n])
    manifest = {str(p): {'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(pathlib.Path('data').glob('*.bin'))}
    pathlib.Path('results/inputs.json').write_text(json.dumps(manifest, indent=2)+'\n')

def case(name, src, flags=(), api='cli', io_mode='file-file', separate=False, reference=True, tools=False, decode_flags=()):
    archive = f'results/{name}.zst'
    expected = sha(src)
    if api == 'cli':
        cmd = [ZEEK, 'compress', '-q', '-f', *flags]
        stdin = src if io_mode.startswith('stdin') else None
        cmd += ['-'] if stdin else [src]
        output = archive if io_mode.endswith('stdout') else None
        cmd += ['-c'] if output else ['-o', archive]
        if separate: cmd += ['--seek-table-file', archive+'.table']
    else:
        cmd = [PROBE, 'encode', src, archive, *flags]
        stdin = output = None
    encoded = run(name, 'encode', cmd, stdin, output)
    if encoded['rc']: return
    run(name, 'zstd', ['zstd', '-d', '-c', *decode_flags, archive], expected=expected)
    if reference: run(name, 'reference', [PROBE, 'oracle', archive, src], expected=expected)
    if tools:
        for tool, args in [('unzstd',['-c']), ('zstdcat',[]), ('zstdmt',['-d','-c']), ('pzstd',['-d','-c'])]:
            run(name, tool, [tool, *args, *decode_flags, archive], expected=expected)
        run(name, 'zstd-pipe', ['zstd','-d','-c', *decode_flags], stdin=archive, expected=expected)
        run(name, 'test', ['zstd','-t',*decode_flags,archive])
        run(name, 'list', ['zstd','-lv',archive])
    return archive

def cli():
    jobs=[]
    # Broad interactions on four distinct data distributions; no dictionary.
    for kind, policy, size, level, checksum in itertools.product(['text','dense','random','mixed'], ['uncompressed','compressed'], [127,4096,131072,2097152], [-5,0,1,3,9,19,22], [False,True]):
        name=f'cli-{kind}-{policy[0]}-s{size}-l{level}-c{int(checksum)}'
        flags=['--frame-size-policy',policy,'-s',str(size),f'--compression-level={level}']
        if not checksum: flags+=['--no-checksum']
        jobs.append((name,f'data/{kind}.bin',flags))
    # Exact input boundaries and both checksum settings, using the default 2 MiB policy.
    for src, checksum in itertools.product(sorted(pathlib.Path('data').glob('n*.bin')), [False,True]):
        jobs.append((f'boundary-{src.stem}-c{int(checksum)}',str(src),[] if checksum else ['--no-checksum']))
    # Very small frames and full I/O/sidecar combinations.
    for size, policy in itertools.product([1,2,3,9],['uncompressed','compressed']):
        jobs.append((f'tiny-{policy[0]}-{size}','data/dense.bin',['-s',str(size),'--frame-size-policy',policy]))
    with cf.ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda j: case(*j),jobs))
    for src, mode, separate in itertools.product(['data/empty.bin','data/mixed.bin','data/n4194305.bin'], ['file-file','stdin-file','file-stdout','stdin-stdout'], [False,True]):
        name=f'io-{pathlib.Path(src).stem}-{mode}-side{int(separate)}'
        case(name,src,io_mode=mode,separate=separate,reference=not separate,tools=True)

def library():
    jobs=[]
    for api, policy, buffers, checksum, schedule in itertools.product(['raw','writer'],['u','c'],[(1,1),(7,3),(127,13),(4093,131591),(131072,262144)],[0,1],['plain','flush','end','both']):
        inc,outc=buffers
        # One-byte schedules over 4 KiB keep the intentional tiny-block tests bounded.
        src='data/n4097.bin' if inc < 127 else 'data/random.bin'
        opts=[f'api={api}',f'policy={policy}','frame=4096',f'in={inc}',f'out={outc}',f'checksum={checksum}']
        if schedule in ('flush','both'): opts += ['flush=3']
        if schedule in ('end','both'): opts += ['end=5']
        if api == 'writer': opts += ['short=7']
        jobs.append((f'lib-{api}-{policy}-i{inc}-o{outc}-c{checksum}-{schedule}',src,opts))
    with cf.ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda j: case(*j,api='library'),jobs))
    for api, fmt, side, src in itertools.product(['raw','writer'],['foot','head'],[0,1],['data/empty.bin','data/mixed.bin']):
        case(f'layout-{api}-{fmt}-side{side}-{pathlib.Path(src).stem}',src,[f'api={api}',f'format={fmt}',f'separate={side}','frame=4096','out=1'],api='library',reference=fmt=='foot' and not side,tools=True)
    for opts in [[],['content=0'],['pledge=1'],['pledge=1','content=0'],['window=10'],['window=27'],['workers=2']]:
        case('context-'+('-'.join(opts) or 'default'),'data/mixed.bin',opts,api='library')

def large():
    zero='data/zero-4g.bin'; noise='data/random-4g.bin'
    with open(zero,'wb') as f: f.truncate((1<<32)+17)
    r=random.Random(1827357)
    with open(noise,'wb') as f:
        for _ in range(256): f.write(r.randbytes(1<<24))
        f.write(r.randbytes(1048593))
    for src in [zero,noise]:
        for policy,size in [('uncompressed','2M'),('uncompressed','4294967295'),('compressed','4294967295')]:
            name=f'large-{pathlib.Path(src).stem}-{policy[0]}-{size}'
            case(name,src,['--frame-size-policy',policy,'-s',size],tools=True)
    case('large-library-raw',noise,['api=raw','policy=c','frame=4294967295','in=1048579','out=65537','checksum=1'],api='library')
    # Deliberately valid large-window stream, above the distro CLI default limit.
    src='data/window-input.bin'
    with open(src,'wb') as f: f.truncate(300<<20)
    case('large-window',src,['window=28','frame=1073741824','checksum=1'],api='library',reference=True)
    run('large-window','zstd-raised',['zstd','-d','-c','--memory=256MB','results/large-window.zst'],expected=sha(src))

def special():
    # Prefix dependency across several frames and both prefix loading paths.
    for policy, mmap, side, checksum in itertools.product(['uncompressed','compressed'],['--mmap-prefix','--no-mmap-prefix'],[False,True],[False,True]):
        name=f'patch-{policy[0]}-{mmap[2:]}-side{int(side)}-c{int(checksum)}'
        opts=['--patch-from','data/prefix.bin',mmap,'--frame-size-policy',policy,'-s','131072']
        if not checksum: opts+=['--no-checksum']
        archive=case(name,'data/patched.bin',opts,separate=side,reference=False)
        expected=sha('data/patched.bin')
        run(name,'zstd-patch',['zstd','-d','-c','--patch-from=data/prefix.bin',archive],expected=expected)
        run(name,'zstd-dict',['zstd','-d','-c','-D','data/prefix.bin',archive],expected=expected)
    for api in ['raw','writer']:
        for dep in ['dict','prefix']:
            name=f'dependency-{api}-{dep}'
            archive=case(name,'data/patched.bin',[f'api={api}',f'{dep}=data/prefix.bin','frame=131072','checksum=1'],api='library',reference=False)
            run(name,'zstd-dict',['zstd','-d','-c','-D','data/prefix.bin',archive],expected=sha('data/patched.bin'))
            run(name,'zstd-patch',['zstd','-d','-c','--patch-from=data/prefix.bin',archive],expected=sha('data/patched.bin'))
    # Explicitly show reference compatibility of the supported layouts.
    for name in ['layout-writer-head-side0-mixed','layout-writer-foot-side1-mixed']:
        run(name,'reference-layout',[PROBE,'oracle',f'results/{name}.zst','data/mixed.bin'],expected=sha('data/mixed.bin'))

if __name__ == '__main__':
    RECORDS.write_text('')
    if STAGE == 'inputs': inputs()
    elif STAGE == 'cli': cli()
    elif STAGE == 'library': library()
    elif STAGE == 'large': large()
    elif STAGE == 'special': special()
    else: raise ValueError(STAGE)
    print('DONE', STAGE, flush=True)
