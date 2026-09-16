#!/usr/bin/env python3
"""Recover a zeekstd Foot patch using only Python's stdlib and the zstd CLI.
Usage: python3 scripts/recover_patch.py ARCHIVE BASE [MEMORY] > restored
For intact archives produced by the tested writer; not an untrusted-input parser.
Each data frame gets its own --patch-from invocation, so the base is reapplied.
"""
import pathlib, struct, subprocess, sys, tempfile
archive, base = sys.argv[1:3]
memory=sys.argv[3] if len(sys.argv)>3 else '256MB'
with open(archive,'rb') as f:
    f.seek(-9,2)
    count, descriptor, magic = struct.unpack('<IBI',f.read(9))
    assert magic==0x8f92eab1 and descriptor==0
    f.seek(-(17+8*count),2)
    skippable,size=struct.unpack('<II',f.read(8))
    assert skippable==0x184d2a5e and size==9+8*count
    entries=[struct.unpack('<II',f.read(8)) for _ in range(count)]
    f.seek(0)
    with tempfile.TemporaryDirectory(prefix='patch-recovery-',dir=pathlib.Path(archive).parent) as tmp:
        frame=pathlib.Path(tmp)/'frame.zst'
        for compressed,uncompressed in entries:
            frame.write_bytes(f.read(compressed))
            p=subprocess.run(['zstd','-d','-c','--memory='+memory,'--patch-from='+base,str(frame)],stdout=sys.stdout.buffer)
            if p.returncode: sys.exit(p.returncode)
