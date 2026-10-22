"""Install (or restore) the DevGUI pause-menu .iggy files into game1_patch.

Dry run by default; pass --apply to write. The game must be closed.
  repack_pause_devgui.py [--apply]     append patched files, repoint index entries
  repack_pause_devgui.py --restore     put the backed-up index back
Every index entry whose path is ui/emily_pause_menu.iggy or
ui/corvo_pause_menu.iggy is repointed (>QII offset,size,size; data stored
uncompressed, 16-byte aligned, appended to game1_patch.resources).
"""
import hashlib, os, shutil, struct, sys, zlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from idx import parse

BASE = 'C:/Program Files (x86)/Steam/steamapps/common/Dishonored2/base/'
INDEX = BASE + 'game1_patch.index'
RESOURCES = BASE + 'game1_patch.resources'
BACKUP = INDEX + '.bak-devgui'
SIZE_NOTE = RESOURCES + '.size-before-devgui'
HERE = os.path.dirname(os.path.abspath(__file__))
FILES = {
    'ui/emily_pause_menu.iggy': (HERE + '/ui_emily_pause_menu.iggy',
                                 HERE + '/emily_pause_menu.patched.iggy'),
    'ui/corvo_pause_menu.iggy': (HERE + '/ui_corvo_pause_menu.iggy',
                                 HERE + '/corvo_pause_menu.patched.iggy'),
}
PATCH_CONTAINER = 24


def sha(b):
    return hashlib.sha256(b).hexdigest()[:16]


def read_entry(e):
    with open(RESOURCES, 'rb') as h:
        h.seek(e['off']); raw = h.read(e['zsize'])
    return raw if e['zsize'] == e['size'] else zlib.decompress(raw[2:], -15)


def extract_and_patch(entries):
    """Writes the original .iggy files from the archive and their patched copies
    next to this script (game data; not committed)."""
    import subprocess
    for path, (original, patched) in FILES.items():
        if os.path.exists(original) and os.path.exists(patched):
            continue
        e = next(x for x in entries if x['path'] == path)
        open(original, 'wb').write(read_entry(e))
        subprocess.check_call([sys.executable, '-I', os.path.join(HERE, 'patch_pause_devgui.py'),
                               original, patched], cwd=HERE)


def main():
    apply = '--apply' in sys.argv
    if '--restore' in sys.argv:
        if not os.path.exists(BACKUP):
            raise SystemExit('no backup at ' + BACKUP)
        shutil.copyfile(BACKUP, INDEX)
        print('restored', INDEX, 'from', BACKUP)
        return
    data, entries = parse(INDEX)
    extract_and_patch(entries)
    plan = []
    for path, (original, patched) in FILES.items():
        orig = open(original, 'rb').read(); new = open(patched, 'rb').read()
        hits = [e for e in entries if e['path'] == path]
        if not hits:
            raise SystemExit('no index entry for ' + path)
        for e in hits:
            if e['container'] != PATCH_CONTAINER:
                raise SystemExit('%s entry %d is in container %d' % (path, e['id'], e['container']))
            current = read_entry(e)
            state = 'original' if current == orig else 'patched' if current == new else 'unknown'
            print('%-28s id %5d  off 0x%x  size %d  -> %s (%s)' %
                  (path, e['id'], e['off'], e['size'], state, sha(current)))
            if state == 'unknown':
                raise SystemExit('unexpected contents; refusing to patch')
        plan.append((path, new, hits))
    if not apply:
        print('dry run: pass --apply (game closed) to write')
        return
    if not os.path.exists(BACKUP):
        shutil.copyfile(INDEX, BACKUP)
        open(SIZE_NOTE, 'w').write(str(os.path.getsize(RESOURCES)))
        print('backed up index to', BACKUP)
    index = bytearray(data)
    with open(RESOURCES, 'r+b') as h:
        for path, new, hits in plan:
            h.seek(0, 2); end = h.tell()
            pad = (-end) % 16
            h.write(b'\0' * pad); offset = end + pad
            h.write(new)
            for e in hits:
                struct.pack_into('>QII', index, e['entry_off'], offset, len(new), len(new))
            print('appended %s at 0x%x (%d bytes); repointed %d entries' %
                  (path, offset, len(new), len(hits)))
    open(INDEX, 'wb').write(index)
    data2, entries2 = parse(INDEX)
    for path, new, hits in plan:
        for e in (x for x in entries2 if x['path'] == path):
            assert read_entry(e) == new
    print('verified; restore with: repack_pause_devgui.py --restore')


if __name__ == '__main__':
    main()
