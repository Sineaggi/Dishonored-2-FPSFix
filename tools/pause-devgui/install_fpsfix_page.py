"""Add an "- FPSFIX -" column to DevGUI (debug/devgui_main) backed by the
plugin's fpsfix_* cvars.

Dry run by default; --apply (game closed) writes, --restore puts the index
back. Writes into game1_patch:
  * debug/devgui_main with one more item ("- FPSFIX -" -> debug/devgui_fpsfix),
    appended uncompressed; its index entries are repointed to container 24;
  * a new DevGui_Menu decl debug/devgui_fpsfix (one new index entry; the
    entry count at 0x20 and the size field at 0x04 are updated).
The index is backed up to game1_patch.index.bak-fpsfix-page first.
"""
import os
import shutil
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from idx import parse

BASE = 'C:/Program Files (x86)/Steam/steamapps/common/Dishonored2/base/'
INDEX = BASE + 'game1_patch.index'
RESOURCES = BASE + 'game1_patch.resources'
BACKUP = INDEX + '.bak-fpsfix-page'
CONTAINER_FILES = {0: 'game1.resources', 4: 'game1_001.resources', 8: 'game1_002.resources',
                   12: 'game1_003.resources', 16: 'game1_004.resources',
                   20: 'game1_005.resources', 24: 'game1_patch.resources'}
PATCH_CONTAINER = 24
MAIN_NAME = 'debug/devgui_main'
PAGE_NAME = 'debug/devgui_fpsfix'
PAGE_PATH = 'generated/decls/devgui_menu/debug/devgui_fpsfix.decl'
MARKER = '- FPSFIX -'

# (row name, command, linked cvar) ; None = divider
ROWS = [
    ('Camera Prediction (F10)', 'toggle fpsfix_camera', 'fpsfix_camera'),
    ('World Transforms', 'toggle fpsfix_transforms', 'fpsfix_transforms'),
    ('Source-Level Method', 'toggle fpsfix_source', 'fpsfix_source'),
    ('Skeletons', 'toggle fpsfix_skeletons', 'fpsfix_skeletons'),
    ('First-Person Hands', 'toggle fpsfix_hands', 'fpsfix_hands'),
    None,
    ('Screen Particle Fix (0-3)', 'toggle fpsfix_screenParticles 0 1 2 3',
     'fpsfix_screenParticles'),
    ('Force Blood Effect (Alt+F10)', 'toggle fpsfix_blood', 'fpsfix_blood'),
    ('A/B Recording (Ctrl+F11)', 'toggle fpsfix_abRecord', 'fpsfix_abRecord'),
    None,
    ('Frames/s', '', 'fpsfix_fps'),
    ('Plugin ms: model', '', 'fpsfix_modelMs'),
    ('Plugin ms: pose', '', 'fpsfix_poseMs'),
    ('Plugin ms: flush', '', 'fpsfix_flushMs'),
]


def item(key, name, command, cvar, divider=False, submenu='NULL'):
    return ('\t\t\titem_add["%s"] = {\n'
            '\t\t\t\tm_divider = %s;\n'
            '\t\t\t\tm_inverseCVarValue = false;\n'
            '\t\t\t\tm_name = "%s";\n'
            '\t\t\t\tm_command = "%s";\n'
            '\t\t\t\tm_linkedCVar = "%s";\n'
            '\t\t\t\tm_subMenu = %s;\n'
            '\t\t\t}\n') % (key, 'true' if divider else 'false', name, command, cvar, submenu)


def page_decl():
    body = ''
    for index, row in enumerate(ROWS):
        key = '%d00000' % (index + 1)
        if row is None:
            body += item(key, '', '', '', divider=True)
        else:
            body += item(key, *row)
    return ('{\n\tedit = {\n\t\tm_items = {\n\t\t\titem_begin = true;\n' + body +
            '\t\t}\n\t}\n}\n').encode('ascii')


def read_entry(e):
    path = BASE + CONTAINER_FILES[e['container']]
    with open(path, 'rb') as h:
        h.seek(e['off'])
        raw = h.read(e['zsize'])
    return raw if e['zsize'] == e['size'] else zlib.decompress(raw[2:], -15)


def patched_main(original):
    text = original.decode('latin1')
    if MARKER in text:
        raise SystemExit('devgui_main already has the FPSFIX column')
    end = text.rstrip().rfind('\t\t}')  # closes m_items
    if end < 0:
        raise SystemExit('unexpected devgui_main layout')
    new = (text[:end] + item('700000', MARKER, '', '', submenu='"%s"' % PAGE_NAME) +
           text[end:])
    return new.encode('latin1')


def encode_string(value):
    data = value.encode('latin1')
    return struct.pack('<I', len(data)) + data


def main():
    if '--restore' in sys.argv:
        if not os.path.exists(BACKUP):
            raise SystemExit('no backup at ' + BACKUP)
        shutil.copyfile(BACKUP, INDEX)
        print('restored', INDEX, 'from', BACKUP)
        return
    data, entries = parse(INDEX)
    mains = [e for e in entries if e['name'] == MAIN_NAME and e['path'].endswith('.decl')]
    if not mains:
        raise SystemExit('no %s entry' % MAIN_NAME)
    if any(e['name'] == PAGE_NAME for e in entries):
        raise SystemExit('%s already present; run --restore first' % PAGE_NAME)
    original = read_entry(mains[0])
    main_new = patched_main(original)
    page = page_decl()
    patch_tail = next(e['tail'] for e in entries if e['container'] == PATCH_CONTAINER and
                      e['path'].endswith('.decl'))
    print('%s: %d entries, container %d, %d -> %d bytes' %
          (MAIN_NAME, len(mains), mains[0]['container'], len(original), len(main_new)))
    print('%s: %d bytes, %d rows' % (PAGE_NAME, len(page), len(ROWS)))
    print('patch-container tail %s; new entry id %d' %
          (patch_tail.hex(), max(e['id'] for e in entries) + 1))
    if '--apply' not in sys.argv:
        sys.stdout.write(main_new.decode('latin1')[-500:] + '\n')
        print('dry run: pass --apply (game closed) to write')
        return
    if not os.path.exists(BACKUP):
        shutil.copyfile(INDEX, BACKUP)
        print('backed up index to', BACKUP)
    index = bytearray(data)
    offsets = {}
    with open(RESOURCES, 'r+b') as h:
        for name, blob in ((MAIN_NAME, main_new), (PAGE_NAME, page)):
            h.seek(0, 2)
            end = h.tell()
            pad = (-end) % 16
            h.write(b'\0' * pad)
            offsets[name] = end + pad
            h.write(blob)
    for e in mains:
        struct.pack_into('>QII', index, e['entry_off'], offsets[MAIN_NAME], len(main_new),
                         len(main_new))
        index[e['entry_off'] + 16:e['entry_off'] + 26] = patch_tail
    new_id = max(e['id'] for e in entries) + 1
    record = (struct.pack('>I', new_id) + encode_string('DevGui_Menu') +
              encode_string(PAGE_NAME) + encode_string(PAGE_PATH) +
              struct.pack('>QII', offsets[PAGE_NAME], len(page), len(page)) + patch_tail)
    index += record
    count = struct.unpack_from('>I', index, 0x20)[0]
    struct.pack_into('>I', index, 0x20, count + 1)
    struct.pack_into('>I', index, 0x04, len(index) - 0x20)
    open(INDEX, 'wb').write(index)
    _, check = parse(INDEX)
    assert any(e['name'] == PAGE_NAME for e in check)
    for e in check:
        if e['name'] == MAIN_NAME and e['path'].endswith('.decl'):
            assert read_entry(e) == main_new
        if e['name'] == PAGE_NAME:
            assert read_entry(e) == page
    print('installed; restore with: install_fpsfix_page.py --restore')


if __name__ == '__main__':
    main()
