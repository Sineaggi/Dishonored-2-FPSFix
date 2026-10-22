import struct, sys, re

class R:
    def __init__(s, d, p): s.d = d; s.p = p
    def u8(s): v = s.d[s.p]; s.p += 1; return v
    def u16(s): v = struct.unpack_from('<H', s.d, s.p)[0]; s.p += 2; return v
    def s24(s):
        b = s.d[s.p:s.p+3]; s.p += 3
        v = b[0] | (b[1] << 8) | (b[2] << 16)
        return v - (1 << 24) if v & 0x800000 else v
    def u30(s):
        v = 0; sh = 0
        for _ in range(5):
            b = s.u8(); v |= (b & 0x7f) << sh; sh += 7
            if not b & 0x80: break
        return v
    def d64(s): v = struct.unpack_from('<d', s.d, s.p)[0]; s.p += 8; return v

def parse(d, p):
    r = R(d, p)
    minor, major = r.u16(), r.u16()
    assert (minor, major) == (16, 46)
    ints = [0] + [r.u30() for _ in range(max(0, r.u30() - 1))]
    n = r.u30(); uints = [0] + [r.u30() for _ in range(max(0, n - 1))]
    n = r.u30(); dbl = [0] + [r.d64() for _ in range(max(0, n - 1))]
    n = r.u30(); strs = ['*']
    for _ in range(max(0, n - 1)):
        l = r.u30(); strs.append(d[r.p:r.p+l].decode('utf8', 'replace')); r.p += l
    n = r.u30(); ns = [None]
    for _ in range(max(0, n - 1)): k = r.u8(); ns.append((k, strs[r.u30()]))
    n = r.u30(); nss = [None]
    for _ in range(max(0, n - 1)): nss.append([r.u30() for _ in range(r.u30())])
    n = r.u30(); mn = [None]
    for _ in range(max(0, n - 1)):
        k = r.u8()
        if k in (7, 0x0d): nsi, ni = r.u30(), r.u30(); mn.append(strs[ni])
        elif k in (0x0f, 0x10): mn.append(strs[r.u30()])
        elif k in (0x11, 0x12): mn.append('<rtqnl>')
        elif k in (9, 0x0e): ni = r.u30(); r.u30(); mn.append(strs[ni])
        elif k in (0x1b, 0x1c): r.u30(); mn.append('<mnl>')
        elif k == 0x1d:
            base = r.u30(); params = [r.u30() for _ in range(r.u30())]; mn.append(('generic', base, params))
        else: raise Exception('mn kind %x at %x' % (k, r.p))
    mcount_pos = r.p; n = r.u30(); methods = []; minfo = []
    for _ in range(n):
        mstart = r.p
        pc = r.u30(); r.u30(); [r.u30() for _ in range(pc)]; name = r.u30(); flags = r.u8()
        if flags & 0x08:
            for _ in range(r.u30()): r.u30(); r.u8()
        if flags & 0x80: [r.u30() for _ in range(pc)]
        methods.append(strs[name]); minfo.append((mstart, r.p))
    mend = r.p
    for _ in range(r.u30()):
        r.u30(); [ (r.u30(), r.u30()) for _ in range(r.u30())]
    tpos = {}
    def traits(owner, out):
        cpos = r.p
        for _ in range(r.u30()):
            name = r.u30(); kind = r.u8(); k = kind & 0x0f
            if k in (0, 6): r.u30(); r.u30(); vi = r.u30();  (r.u8() if vi else None)
            elif k in (1, 2, 3): r.u30(); m = r.u30(); out.append((owner, mn[name], m))
            elif k == 4: r.u30(); r.u30()
            elif k == 5: r.u30(); r.u30()
            if kind & 0x40: [r.u30() for _ in range(r.u30())]
        tpos.setdefault(owner, (cpos, r.p))
    nc = r.u30(); inst = []; tr = []
    for _ in range(nc):
        name = r.u30(); r.u30(); fl = r.u8()
        if fl & 0x08: r.u30()
        [r.u30() for _ in range(r.u30())]
        iinit = r.u30(); inst.append(mn[name]); tr.append((mn[name], 'iinit', iinit))
        traits(mn[name], tr)
    for i in range(nc):
        cinit = r.u30(); traits(inst[i] + '$', tr)
    for _ in range(r.u30()): r.u30(); traits('script', tr)
    bodies = {}; bodyinfo = {}
    nb_pos = r.p; bcount_pos = r.p
    for _ in range(r.u30()):
        start = r.p
        m = r.u30(); ms_pos = r.p; ms = r.u30(); lc_pos = r.p; lc = r.u30(); isd = r.u30(); msd = r.u30()
        cl_pos = r.p; cl = r.u30(); code_pos = r.p; code = d[r.p:r.p+cl]; r.p += cl
        bodyinfo[m] = dict(start=start, max_stack=ms, ms_pos=ms_pos, local_count=lc, lc_pos=lc_pos, init_scope=isd, max_scope=msd, cl_pos=cl_pos, code_pos=code_pos, code_len=cl)
        for _ in range(r.u30()): r.u30(); r.u30(); r.u30(); r.u30(); r.u30()
        traits("body", [])
        bodies[m] = code; bodyinfo[m]['end'] = r.p
    return dict(strs=strs, mn=mn, ints=ints, methods=methods, traits=tr, bodies=bodies, bodyinfo=bodyinfo, end=r.p, nb_pos=nb_pos, mcount_pos=mcount_pos, mend=mend, minfo=minfo, tpos=tpos, bend=r.p)

OPS = {0x24:('pushbyte','b'),0x25:('pushshort','u'),0x2c:('pushstring','s'),0x2d:('pushint','i'),
 0x26:('pushtrue',''),0x27:('pushfalse',''),0x20:('pushnull',''),0x21:('pushundefined',''),
 0x60:('getlex','m'),0x66:('getproperty','m'),0x61:('setproperty','m'),0x68:('initproperty','m'),
 0x5d:('findpropstrict','m'),0x5e:('findproperty','m'),0x46:('callproperty','mu'),0x4f:('callpropvoid','mu'),
 0x4a:('constructprop','mu'),0x41:('call','u'),0x42:('construct','u'),0x45:('callsuper','mu'),0x4e:('callsupervoid','mu'),
 0x10:('jump','j'),0x11:('iftrue','j'),0x12:('iffalse','j'),0x13:('ifeq','j'),0x14:('ifne','j'),0x15:('iflt','j'),
 0x16:('ifle','j'),0x17:('ifgt','j'),0x18:('ifge','j'),0x19:('ifstricteq','j'),0x1a:('ifstrictne','j'),0x0c:('ifnlt','j'),
 0x0d:('ifnle','j'),0x0e:('ifngt','j'),0x0f:('ifnge','j'),
 0xd0:('getlocal0',''),0xd1:('getlocal1',''),0xd2:('getlocal2',''),0xd3:('getlocal3',''),0x62:('getlocal','u'),
 0xd4:('setlocal0',''),0xd5:('setlocal1',''),0xd6:('setlocal2',''),0xd7:('setlocal3',''),0x63:('setlocal','u'),
 0x30:('pushscope',''),0x47:('returnvoid',''),0x48:('returnvalue',''),0x29:('pop',''),0x2a:('dup',''),0x2b:('swap',''),
 0x6c:('getslot','u'),0x6d:('setslot','u'),0x56:('newarray','u'),0x55:('newobject','u'),0x80:('coerce','m'),
 0x85:('coerce_s',''),0x82:('coerce_a',''),0x76:('convert_b',''),0x73:('convert_i',''),0x96:('not',''),0xa0:('add',''),
 0xab:('equals',''),0xad:('lessthan',''),0x91:('increment',''),0xc0:('increment_i',''),0x02:('nop',''),0x09:('label',''),
 0x2f:('pushdouble','u'),0x74:('convert_u',''),0x75:('convert_d',''),0x87:('astypelate',''),0x86:('astype','m'),
 0x65:('getscopeobject','u'),0x64:('getglobalscope',''),0x6a:('deleteproperty','m'),0x1b:('lookupswitch','x'),
 0x08:('kill','u'),0x32:('hasnext2','uu'),0x1e:('nextname',''),0x23:('nextvalue',''),0x2e:('pushuint','u'),
 0x03:('throw',''),0xa1:('subtract',''),0xa2:('multiply',''),0xa3:('divide',''),0xaf:('greaterthan',''),0xb0:('greaterequals',''),
 0xae:('lessequals',''),0x97:('bitnot',''),0x93:('decrement',''),0x58:('newclass','u'),0x40:('newfunction','u'),
 0xb3:('istypelate',''),0xb2:('istype','m'),0x6e:('getglobalslot','u'),0x6f:('setglobalslot','u'),0x59:('getdescendants','m'),
 0x5a:('newcatch','u'),0x1c:('pushwith',''),0x1d:('popscope',''),0x57:('newactivation',''),0x28:('pushnan',''),
 0xa8:('bitand',''),0xa9:('bitor',''),0xaa:('bitxor',''),0xa5:('lshift',''),0xa6:('rshift',''),0xc5:('add_i',''),
 0x04:('getsuper','m'),0x05:('setsuper','m'),0xc2:('inclocal_i','u'),0x92:('inclocal','u'),0x94:('declocal','u'),
 0x95:('typeof',''),0xc1:('decrement_i',''),0x83:('coerce_i',''),0x90:('negate',''),0xb4:('in',''),0xac:('strictequals',''),
 0xb1:('instanceof',''),0xa4:('modulo',''),0x87:('astypelate','')}

def dis(abc, code):
    r = R(code, 0); out = []
    while r.p < len(code):
        at = r.p; op = r.u8()
        if op not in OPS: out.append('%04x ?? %02x' % (at, op)); break
        nm, a = OPS[op]; args = []
        for c in a:
            if c == 'b': args.append(str(struct.unpack('b', bytes([r.u8()]))[0]))
            elif c == 'u': args.append(str(r.u30()))
            elif c == 'i': args.append(str(abc['ints'][r.u30()]) if False else 'int#'+str(r.u30()))
            elif c == 's': args.append(repr(abc['strs'][r.u30()]))
            elif c == 'm': args.append(str(abc['mn'][r.u30()]))
            elif c == 'j': args.append('->%04x' % (r.p + 3 + r.s24()))
            elif c == 'x':
                base = at; df = r.s24(); cnt = r.u30(); [r.s24() for _ in range(cnt + 1)]
        out.append('%04x %s %s' % (at, nm, ' '.join(args)))
    return out

if __name__ == '__main__':
    d = open(sys.argv[1], 'rb').read()
    for m in re.finditer(b'\x10\x00\x2e\x00', d):
        try:
            abc = parse(d, m.start())
        except Exception as e:
            continue
        hits = [t for t in abc['traits'] if any(k in str(t[1]) for k in sys.argv[2:])]
        if hits:
            print('ABC at', hex(m.start()), 'end', hex(abc['end']))
            for owner, name, mi in hits:
                print('=== %s.%s (method %d)' % (owner, name, mi))
                if mi in abc['bodies']:
                    print('\n'.join(dis(abc, abc['bodies'][mi])))
