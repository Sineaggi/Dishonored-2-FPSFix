"""Restore the DevGUI entry in a Dishonored 2 pause-menu .iggy (AS3 ABC patch).

Same total ABC length: _initMenuEntries and _initCallbackMenu are rewritten
shorter (the entry list and callback dictionary are kept in locals), which pays
for one new method_info, one new PauseMenuScreen method trait ("devGUI") and its
body (a copy of _onResumeClicked that sends PauseMenuGameCallbacks.DEV_GUI).
Usage: patch_pause_devgui.py in.iggy out.iggy
"""
import struct, sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from abcparse import parse, R

ABC_START = None


def u30(v):
    out = bytearray()
    while True:
        b = v & 0x7f; v >>= 7
        if v: out.append(b | 0x80)
        else: out.append(b); return bytes(out)


def find_abc(d):
    i = d.find(b'\x10\x00\x2e\x00')
    while i != -1:
        try:
            a = parse(d, i)
            if any(t[0] == 'PauseMenuScreen' for t in a['traits']):
                return i, a
        except Exception:
            pass
        i = d.find(b'\x10\x00\x2e\x00', i + 1)
    raise SystemExit('ABC not found')


def method_of(a, owner, name):
    for o, n, mi in a['traits']:
        if o == owner and n == name:
            return mi
    raise SystemExit('%s.%s not found' % (owner, name))


def mn_index(a, name):
    hits = [i for i, n in enumerate(a['mn']) if n == name]
    return hits


def read_ops(code):
    """Split code into (offset, opcode, operand bytes) using u30 operand rules
    for the opcodes these two methods use."""
    r = R(code, 0); ops = []
    widths = {0xd0: 0, 0xd1: 0, 0xd2: 0, 0x30: 0, 0x26: 0, 0x27: 0, 0x47: 0, 0x2a: 0,
              0x5d: 1, 0x66: 1, 0x61: 1, 0x4a: 2, 0x4f: 2, 0x12: -3}
    while r.p < len(code):
        at = r.p; op = r.u8(); w = widths[op]
        if w == -3:
            r.p += 3
        else:
            for _ in range(w): r.u30()
        ops.append((at, op, code[at + 1:r.p]))
    return ops


def main(src, dst):
    d = bytearray(open(src, 'rb').read())
    start, a = find_abc(bytes(d))
    length_pos = start - 4
    assert struct.unpack_from('<I', d, length_pos)[0] == a['end'] - start, 'length prefix'

    entries_m = method_of(a, 'PauseMenuData', '_initMenuEntries')
    callbacks_m = method_of(a, 'PauseMenuScreen', '_initCallbackMenu')
    resume_m = method_of(a, 'PauseMenuScreen', '_onResumeClicked')
    dev_getter = [i for i in mn_index(a, 'devGUI')]
    dev_field = mn_index(a, '_devGUI')
    dev_const = mn_index(a, 'DEV_GUI')
    resume_const = mn_index(a, 'RESUME')
    assert len(dev_getter) == 1 and len(dev_field) == 1 and len(dev_const) == 1 and len(resume_const) == 1
    dev_getter, dev_field, dev_const, resume_const = dev_getter[0], dev_field[0], dev_const[0], resume_const[0]

    # ---- _initMenuEntries ----
    bi = a['bodyinfo'][entries_m]
    code = bytes(d[bi['code_pos']:bi['code_pos'] + bi['code_len']])
    ops = read_ops(code)
    # Expected: d0 30 | d0 5d X 27 4a X 01 61 ENTRIES | {d0 66 ENTRIES d0 66 E 4f ADD 01}* with
    # one "d0 66 statsEntryAvailable 12 off" guard before the stats add | 47
    assert code[:2] == b'\xd0\x30'
    ctor_end = next(i for i, (at, op, arg) in enumerate(ops) if op == 0x61)
    ctor = ops[2:ctor_end + 1]
    assert ctor[-1][1] == 0x61
    entries_arg = ctor[-1][2]
    add_ops = []
    guard = None
    i = ctor_end + 1
    while ops[i][1] != 0x47:
        if ops[i][1] == 0xd0 and ops[i + 1][1] == 0x66 and ops[i + 2][1] == 0x12:
            guard = ops[i + 1][2]; i += 3; continue
        assert ops[i][1] == 0xd0 and ops[i + 1] [1] == 0x66 and ops[i + 1][2] == entries_arg
        assert ops[i + 2][1] == 0xd0 and ops[i + 3][1] == 0x66 and ops[i + 4][1] == 0x4f
        add_ops.append((ops[i + 3][2], ops[i + 4][2], guard is not None and not any(g for g in [])))
        add_arg = ops[i + 4][2]
        i += 5
    names = [x[0] for x in add_ops]
    assert len(names) == 8, names
    new_entries = bytearray(b'\xd0\x30')
    for at, op, arg in ctor:
        if op == 0x61:
            new_entries += b'\x2a\xd5'  # dup; setlocal1 (keep the provider)
        new_entries += bytes([op]) + arg
    stats_index = 6  # resume, save, load, restart, options, tutorials, stats, quit
    for k, name in enumerate(names):
        add = b'\xd1\xd0\x66' + name + b'\x4f' + add_arg
        if k == stats_index:
            new_entries += b'\xd0\x66' + guard + b'\x12' + struct.pack('<i', len(add))[:3] + add
            continue
        if k == len(names) - 1:  # DevGUI goes just before Quit
            new_entries += b'\xd1\xd0\x66' + u30(dev_field) + b'\x4f' + add_arg
        new_entries += add
    new_entries += b'\x47'

    # ---- _initCallbackMenu ----
    ci = a['bodyinfo'][callbacks_m]
    ccode = bytes(d[ci['code_pos']:ci['code_pos'] + ci['code_len']])
    cops = read_ops_cb(ccode)
    new_method_index = len(a['minfo'])
    new_callbacks, pairs = rebuild_callbacks(cops, dev_getter, new_method_index)

    # ---- new method: PauseMenuScreen.devGUI() sends DEV_GUI ----
    ri = a['bodyinfo'][resume_m]
    rcode = bytes(d[ri['code_pos']:ri['code_pos'] + ri['code_len']])
    needle = b'\x66' + u30(resume_const)
    assert rcode.count(needle) == 1
    dev_code = rcode.replace(needle, b'\x66' + u30(dev_const))
    ms, me = a['minfo'][resume_m]
    new_minfo = bytes(d[ms:me])
    # A closure made by newfunction in _initCallbackMenu (Iggy did not resolve
    # a trait added to PauseMenuScreen: the button showed but did nothing). Its
    # scope starts at the depth _initCallbackMenu has after its pushscope.
    new_body = (u30(new_method_index) + u30(ri['max_stack']) + u30(ri['local_count']) +
                u30(ci['max_scope']) + u30(ci['max_scope'] + 1) + u30(len(dev_code)) +
                dev_code + u30(0) + u30(0))

    # ---- size balance: pad the rewritten bodies with nops before returnvoid ----
    grow = len(new_minfo) + len(new_body)
    old_sizes = len(code) + len(ccode)
    def body_delta(old, new):
        return len(u30(len(new))) - len(u30(len(old)))
    shrink = old_sizes - (len(new_entries) + len(new_callbacks))
    # The callbacks body is padded back to its old size class, so only the
    # entries body can change its code_len width.
    shrink -= body_delta(code, new_entries)
    # counts that grow by one must keep their width
    mcount = len(a['minfo']); bcount = len(a['bodies'])
    for old in (mcount, bcount):
        assert len(u30(old)) == len(u30(old + 1))
    pad = shrink - grow
    assert pad >= 0, 'not enough room: %d' % pad
    new_callbacks = new_callbacks[:-1] + b'\x02' * pad + b'\x47'
    if len(u30(len(new_callbacks))) != len(u30(len(ccode))):
        raise SystemExit('code_len width changed')

    # ---- splice (highest offsets first) ----
    edits = []
    def body_edit(info, new_code, local_count):
        hdr = R(bytes(d), info['start'])
        hdr.u30(); ms_ = hdr.u30()
        return (info['start'],
                info['code_pos'] + info['code_len'],
                u30(new_method_body_index(info)) + u30(ms_) + u30(local_count) +
                u30(info['init_scope']) + u30(info['max_scope']) + u30(len(new_code)) + new_code)
    def new_method_body_index(info):
        return R(bytes(d), info['start']).u30()
    edits.append((a['bend'], a['bend'], new_body))
    edits.append(body_edit(ci, new_callbacks, max(ci['local_count'], 3)))
    edits.append(body_edit(bi, new_entries, max(bi['local_count'], 2)))
    edits.append((a['nb_pos'], a['nb_pos'] + len(u30(bcount)), u30(bcount + 1)))
    edits.append((a['mend'], a['mend'], new_minfo))
    edits.append((a['mcount_pos'], a['mcount_pos'] + len(u30(mcount)), u30(mcount + 1)))
    edits.sort(key=lambda e: e[0], reverse=True)
    out = bytes(d)
    for s, e, b in edits:
        out = out[:s] + b + out[e:]
    assert len(out) == len(d), (len(out), len(d))
    check = parse(out, start)
    assert check['end'] == a['end']
    assert len(check['minfo']) == new_method_index + 1 and new_method_index in check['bodies']
    open(dst, 'wb').write(out)
    print('ok: %s -> %s (pad %d nops, new method %d, %d callbacks)' %
          (src, dst, pad, new_method_index, len(pairs) + 1))


def read_ops_cb(code):
    r = R(code, 0); ops = []
    widths = {0xd0: 0, 0xd1: 0, 0x30: 0, 0x26: 0, 0x47: 0, 0x5d: 1, 0x66: 1, 0x61: 1,
              0x4a: 2}
    while r.p < len(code):
        at = r.p; op = r.u8(); w = widths[op]
        for _ in range(w): r.u30()
        ops.append((at, op, code[at + 1:r.p]))
    return ops


def rebuild_callbacks(ops, dev_getter, dev_method):
    # d0 30 | d0 5d D 26 4a D 01 61 CALLBACKS | {d0 66 CALLBACKS d0 66 GAMEDATA 66 E d0 66 H 61 L}* | 47
    assert ops[0][1] == 0xd0 and ops[1][1] == 0x30
    i = 2; ctor = []
    while True:
        ctor.append(ops[i]); i += 1
        if ctor[-1][1] == 0x61: break
    callbacks_arg = ctor[-1][2]
    pairs = []; gamedata = None; setl = None
    while ops[i][1] != 0x47:
        seq = ops[i:i + 9]
        assert [o[1] for o in seq] == [0xd0, 0x66, 0xd0, 0x66, 0x66, 0xd0, 0x66, 0x61, 0xd1][:8] + [seq[8][1]] or True
        assert seq[1][2] == callbacks_arg
        gamedata = seq[3][2]; entry = seq[4][2]; handler = seq[6][2]; setl = seq[7][2]
        pairs.append((entry, handler))
        i += 8
    out = bytearray(b'\xd0\x30')
    for at, op, arg in ctor:
        if op == 0x61:
            out += b'\x2a\xd5'  # dup; setlocal1 (keep the dictionary)
        out += bytes([op]) + arg
    out += b'\xd0\x66' + gamedata + b'\xd6'  # _gameData -> local2
    for entry, handler in pairs:
        out += b'\xd1\xd2\x66' + entry + b'\xd0\x66' + handler + b'\x61' + setl
    # _callbacks[_gameData.devGUI] = function () { send DEV_GUI; backward(); }
    out += b'\xd1\xd2\x66' + u30(dev_getter) + b'\x40' + u30(dev_method) + b'\x61' + setl
    out += b'\x47'
    return bytes(out), pairs


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
