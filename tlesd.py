#!/usr/bin/env python
import argparse, collections, gzip, logging, os, re, runpy, select, socket, struct, sys, time, traceback
default_initmmc, default_netdefs = 'init.mmc', 'netdefs.le195.mmc'
class G: __slots__ = 'opts net manhole proto world clock'.split()
tcchars, now, pj, exists, basename, deque = 'rgybpcweRGYBPCWE', time.monotonic, os.path.join, os.path.exists, os.path.basename, collections.deque
(tcmap := {'0':'\033[0m'}).update({c:f'\033[38;5;{i+1}m' for i,c in enumerate(tcchars)})
tcpat, tcrfunc, tcnone = re.compile('`([0'+tcchars+'])'), lambda m: tcmap[m[1]], lambda m: ''
def subtc(s): return tcpat.sub(tcrfunc if g.opts.termcolors else tcnone, s)
def striptc(s): return tcpat.sub(tcnone, s)
hlpat, hlrfunc = re.compile('|'.join(f'(?P<{w[0]}>{w[1:]})' for w in r'R\bunknown\b B\b0x[a-f0-9]+\b y\b\d+:\d+(?::\d+)*\b C\b\d+\.\d+(?:\.\d+)*\b b\b\d+\b Y\bcp_\w+\b G\bsp_\w+\b c\b[cuem]\d+\b P\b[A-Z][A-Z_0-9]+\b r\bb\'(?:\\\'|[^\'])*\' g\'(?:\\\'|[^\'])*\' W\bb"(?:\\"|[^"])*" w"(?:\\"|[^"])*"'.split())), lambda m: f'`{m.lastgroup}{m[0]}`0'
def subhl(s): return hlpat.sub(hlrfunc, s) if g.opts.termcolors else s
info, warn, err, dbg = (lambda m, a=k, b=p: getattr(logging, a)(subtc(b+subhl(m)+'`0')) for k,p in (('info',''),('warn','`YWARN`0 '),('error','`RERROR`0 '),('debug','`pDEBUG`0 ')))
def slurp(p): return open(p).read()
def gzopen(p): return ((f.close(), gzip.open(p)) if (f := open(p, 'rb')).read(2) == b'\x1f\x8b' else (f.seek(0), f))[1]
def iterable(o): return hasattr(o, '__iter__') or hasattr(o, '__getitem__')
def hexdump(b, n=16, prefix='', lsep='\n'):
    r = []
    for i in range(0, len(b), n):
        a = b[i:i + n]
        h, p, x = ' '.join(l := [f'{v:02x}' for v in a]), ''.join(chr(v) if 31 < v < 127 else '.' for v in a), ' '*3*(n - len(l))
        r.append(f'{prefix}{i:04x} {h}{x} {p}')
    return r if lsep is None else lsep.join(r)
class Net:
    __slots__ = 'rs ws'.split()
    def __init__(n): n.rs, n.ws = set(), set()
    def reload(n, o, m): n.rs, n.ws = o.rs, o.ws
class Cxn:
    __slots__ = 'sock fd rh rb wb'.split()
    def __init__(c, s, h):
        c.sock, c.fd, c.rh, c.rb, c.wb = s, s.fileno(), h, b'', b''
        s.setblocking(0)
        g.net.rs.add(c)
        dbg(f'new {c} {h}')
    def fileno(c): return c.fd
    def accept(c, h):
        r = Cxn((t := c.sock.accept())[0], h)
        dbg(f'accept {c} {t} {r} {h}')
        return r
    __str__ = __repr__ = lambda c: f'c{c.fd}'
def close_cxn(c):
    g.net.rs.discard(c)
    g.net.ws.discard(c)
    c.sock.close()
    dbg(f'close {c}')
def read_cxn(c):
    r = 0
    while 1:
        try: d = c.sock.recv(4096)
        except BlockingIOError: break
        if not d: break
        c.rb += d
        r += len(d)
    if not r: close_cxn(c)
    return r
def write_cxn(c, d=b'', flush=0):
    pending, sent, w = len(c.wb), 0, g.net.ws
    c.wb += d
    if d and pending and not flush: return
    try:
        while c.wb:
            if (n := c.sock.send(c.wb)) < 1: break
            c.wb, sent = c.wb[n:], sent + n
        if not sent and c.wb: return close_cxn(c)
    except BlockingIOError: pass
    w.add(c) if c.wb else w.discard(c)
class Serv:
    __slots__ = 'port lcxn'.split()
    def listen(s, port, h):
        s.port, s.lcxn = port, Cxn(socket.create_server(('127.0.0.1', port), reuse_port=1), h)
        info(f'{s.__class__.__name__} {s.lcxn} listening on port {port}')
    def reload(s, o, m): s.port, s.lcxn = o.port, o.lcxn
class Manhole(Serv):
    __slots__ = 'rcons'.split()
    def __init__(m): m.rcons = {}
    def setup(m, md=None): return m
    def reload(m, o, md):
        super().reload(o, md)
        m.setup(md)
        m.rcons = o.rcons
class Rcon:
    __slots__ = 'cxn inpy'.split()
    def __init__(r, c): r.cxn, r.inpy = c, 0
def accept_rcon(l):
    g.manhole.rcons[c] = (r := Rcon(c := l.accept(read_rcon)))
    send_rcon(r, f'rcon @ {g.proto.desc} world:port={g.world.port} python:{sys.version}')
def snipto(s, t): return None if (p := s.find(t)) < 0 else s[:p+1]
def throw(e, *a): raise e(*a)
class MatchError(ValueError): pass
def match_prefix(d, s, p=None, what=None, fmt=lambda t:t[0], throw_errors=1):
    if (v := d.get(n := p+s if p else s)): return s,v
    if len(l := [(k[len(p):] if p else k, v) for k,v in d.items() if k.startswith(n)]) > 1: return throw(MatchError, 'ambiguous: '+' '.join(fmt(t) for t in l)) if throw_errors else None
    return l[0] if l else throw(MatchError, f'no {what or "item"} starts with {s!r}') if throw_errors else None
def read_rcon(c):
    if not (r := g.manhole.rcons.get(c)) or not read_cxn(c): return
    while d := snipto(c.rb, b'\n'):
        c.rb, a, e = c.rb[len(d):], d.decode().split(None), 0
        if not a or not (f := a[0].strip()):
            send_rcon(r, '')
            continue
        try: h = rcmd_eval if r.inpy else match_prefix(globals(), f, 'rcmd_', what='command')[1]
        except MatchError as m: e = str(m)
        if not e:
            try: h(r, a if r.inpy else a[1:])
            except: e = traceback.format_exc()
        if e: send_rcon(r, f'ERROR: {e}')
def send_rcon(r, m): write_cxn(r.cxn, subtc(subhl(m)).encode() + b'\n')
def progdesc(netdefs):
    n, f = basename(sys.argv[0]) or 'tlesd.py', lambda k: next(k+':'+' '.join(a.w[1:]) for a in netdefs[''] if a.w[0] == k)
    return f'{n} {f("game")} {f("protocol")}'
def list_funcdocs(p, s=None): return [(n[len(p):], f.__doc__) for n,f in globals().items() if n.startswith(p) and (not s or n.startswith(s, len(p)))]
def rcmd_help(r, a):
    if not (l := list_funcdocs(p := 'rcmd_', a[0] if a else None)): return tsend(f'no such rcmd {a[0]!r}' if a else f'no rcmds')
    m = max(len(n) for n,d in l)
    for n,d in l: send_rcon(r, f'{n}{(m - len(n))*" "} {d or p+n}')
def rcmd_eval(r, a):
    if r.inpy and a and a[0] == 'q': r.inpy = send_rcon(r, 'command input mode')
    else: send_rcon(r, str(eval(s, globals())) if (s := ' '.join(a)) else 'expecting python expression')
def rcmd_python(r, a):
    r.inpy = 1
    send_rcon(r, f'python input mode (send "q" to stop)')
def rcmd_version(r, a): send_rcon(r, g.proto.desc)
def rcmd_fps(r, a):
    if a: g.opts.fps = max(0.01, float(a[0]))
    send_rcon(r, f'fps = {g.opts.fps} ({1e3/g.opts.fps:.3f}ms)')
def rcmd_reload(r, a):
    p, e = __file__, []
    try: m = runpy.run_path(p, init_globals={'g':g})
    except: e.append(f'failed to run {p}\n{traceback.format_exc()}')
    if e: return err(e[0]), send_rcon(r, e[0])
    globals().update(m)
    for k in g.__slots__:
        o, n = getattr(g, k), 0
        if not (C := m.get(o.__class__.__name__)) or not hasattr(C, 'reload'): continue
        try: (n := C()).reload(o, m)
        except: e.append(f'failed to reload {k}\n{traceback.format_exc()}')
        if n: setattr(g, k, n)
    if m := '\n'.join(e): err(m)
    else: info(m := f'reloaded {p}')
    send_rcon(r, m)
def parse_mmc(s, ln_offset=0):
    r = {(k := ''):[]}
    for i,l in enumerate(s.splitlines()):
        if not (t := l.split('#', 1)[0].rstrip()): continue
        if t.startswith('- '): r[k := t[2:]] = []
        else: r[k].append(Token(i + 1 + ln_offset, len(t) - len(v := t.lstrip()), v.split()))
    for k in list(r): r[k] = parse_tokens(r[k])
    return r
class Token:
    __slots__ = 'ln ind words'.split()
    def __init__(t, n, i, l): t.ln, t.ind, t.words = n, i, l
    __str__ = __repr__ = lambda t: f'Token(L{t.ln} ind={t.ind} {t.words})'
class ParseError(RuntimeError): pass
class Parser:
    __slots__ = 'tokens i'.split()
    def __init__(p, l): p.tokens, p.i = l, 0
    def more(p): return p.i < len(p.tokens)
    def peek(p): return p.tokens[p.i]
    def fail(p, m): throw(ParseError, m+'\n  at '+str(p.tokens[p.i] if p.more() else Token(len(p.tokens), 0, ['EOF'])))
    def adv(p): p.i += 1
class Ast:
    __slots__ = 'kind ln w body'.split()
    def __init__(a, k, l, w): a.kind, a.ln, a.w, a.body = k, l, w, []
    __str__ = __repr__ = lambda a: f'Ast(L{a.ln} {a.kind} {a.w} {{{len(a.body)}}})'
def parse_tokens(l):
    p, r, d = Parser(l), [], {}
    while p.more():
        if not (a := p_enum(p) or p_field(p)): p.fail('invalid syntax')
        if a.kind == 'p_enum': d[k] = a if not (o := d.get(k := a.w[0])) else p.fail(f'duplicate key {k!r} for {o} at {a}')
        r.append(a)
    return r
def p_enum(p):
    if (t := p.peek()).ind: p.fail('unexpected enum indent')
    if not (w := t.words[0]).isnumeric(): return None
    a = Ast('p_enum', t.ln, [int(w)] + t.words[1:])
    p.adv()
    while p.more() and p.peek().ind > 0: a.body.append(p_field(p))
    return a
def p_field(p):
    if len((t := p.peek()).words) < 2: p.fail(f'missing field name')
    a = Ast('p_field', t.ln, t.words)
    p.adv()
    while p.more() and p.peek().ind > t.ind: a.body.append(p_field(p))
    return a
def find_asset(p): return next((r for b in g.opts.assetdirs for e in ('', '.gz') if exists(r := pj(b, p+e))), p)
def get_map(n): return g.world.nametab_maps.get(n)
class Model:
    __slots__ = 'i name has_bling'.split()
    def __init__(m, i, n, hb): m.i, m.name, m.has_bling = i, n, hb
def get_model(i):
    if m := (d := g.world.models).get(i): return m
    d[i] = (m := Model(i, n := get_sym('model', i), 0))
    try: m.has_bling = 'standard_players' in slurp(p := find_asset(pj('actor_defs', n+'.xml')))
    except FileNotFoundError: err(f'failed to load model {i} {n!r}, file not found: "{p}"')
    return m
class V2:
    __slots__ = 'x y'.split()
    def __init__(v, x=None, y=None): v.x, v.y = (x.x, x.y) if isinstance(x, V2) else tuple(x)[:2] if iterable(x) else (x or 0,)*2 if y is None else (x or 0, y or 0)
    __str__ = __repr__ = lambda v: f'{v.x},{v.y}'
    __add__ = lambda v,o: V2(v.x+o, v.y+o) if isinstance(o, (int,float)) else V2(v.x+o.x, v.y+o.y)
    __sub__ = lambda v,o: V2(v.x-o, v.y-o) if isinstance(o, (int,float)) else V2(v.x-o.x, v.y-o.y)
    __eq__ = lambda v,o: (v.x,v.y) == (o.x,o.y) if isinstance(o, V2) else NotImplemented
    __hash__ = lambda v: hash((v.x,v.y))
def clamp(a, v, b): return a if v < a else b if v > b else v
def distsq(a, b): return (a.x - b.x)**2 + (a.y - b.y)**2
class Heights:
    __slots__ = 'mv x y'.split()
    def __init__(h, b, x, y): h.mv, h.x, h.y = memoryview(b).cast('B', (y, x)), x, y
    def clampv(h, v): return V2(clamp(0, v.x, (s := h.mv.shape)[1]-1), clamp(0, v.y, s[0]-1))
    def contains(h, v): return 0 <= v.x < (s := h.mv.shape)[1] and 0 <= v.y < s[0]
    size = property(lambda h: V2(h.x, h.y))
    __getitem__ = lambda h,v: h.mv[v.y, v.x]
    __str__ = __repr__ = lambda h: (s := h.mv.shape, f'{s[1]}x{s[0]}')[1]
class Map:
    __slots__ = 'i path error cont name heights startpos'.split()
    def __init__(m, i, p, c): m.i, m.path, m.error, m.cont, m.name, m.heights, m.startpos = i, p, None, c, basename(p).removesuffix('.elm'), None, V2()
    __str__ = __repr__ = lambda m: f'Map({m.i} {m.name} {m.cont} {m.path} {m.heights or m.error})'
    def fail(m, e): m.error = (e, err(e))[0]
def load_heights(m):
    try: fid, x, y, to, ho = struct.unpack_from('<4s4i', (f := gzopen(p := find_asset(m.path))).read(20))
    except FileNotFoundError: return m.fail(f'file not found: {p}')
    if fid != (v := b'elmf'): return m.fail(f'file {p} has wrong file id {fid} (expecting {v})')
    with f: m.heights = (h := Heights((f.seek(ho), f.read(36*x*y))[1], 6*x, 6*y))
    info(f'loaded map heights {h} from {p}')
    return h
def get_heights(m): return None if m.error else m.heights or load_heights(m)
def height_at(m, p): return h[p] if (h := get_heights(m)) and h.contains(p) else 0
class User:
    __slots__ = 'cxn lat ipq opq ent dev thiscmd'.split()
    def __init__(u, c): u.cxn, u.lat, u.ipq, u.opq, u.ent, u.dev, u.thiscmd = c, g.opts.latency * 1e-3, deque(), deque(), None, 1, None
    __str__ = __repr__ = lambda u: f'u{u.cxn.fd if u.cxn else 0}'
    def __enter__(u): g.world.upush(u)
    def __exit__(u, e, v, t): g.world.upop()
class Item:
    __slots__ = 'i image cat name'.split()
    def __init__(i, id, im, c, n): i.i, i.image, i.cat, i.name = id, im, c, n
    __str__ = __repr__ = lambda i: f'{i.i}:{i.name}'
class World(Serv):
    __slots__ = 'users thisuser stu ents maps nametab_maps models items minute'.split()
    def __init__(w): w.users, w.thisuser, w.stu, w.ents, w.maps, w.nametab_maps, w.models, w.items, w.minute = {}, User(0), [], {}, {}, {}, {}, {}, 0
    def setup(w, m=None):
        w.maps = {i:Map(i, (t := l.split())[5], t[0]) for i,l in enumerate(open(find_asset('mapinfo.lst'))) if (t := l.strip()) and not t.startswith('#')}
        w.nametab_maps = {m.name:m for m in w.maps.values()}
        w.maps[0].startpos = V2(75,133)
        w.items = {(i := int(t[0])):Item(i, int(t[1]), int(t[2]), t[3]) for l in open(find_asset('item_info.txt'), encoding='latin1') if len(t := tuple(w.strip() for w in l.split('|'))) == 4}
        return w
    def reload(w, o, m):
        super().reload(o, m)
        w.users, w.thisuser, w.stu, w.ents, w.minute = o.users, o.thisuser, o.stu, o.ents, o.minute
        w.setup(m)
    def upush(w, u): _, w.thisuser = w.stu.append(w.thisuser), u
    def upop(w): w.thisuser = w.stu.pop()
def accept_user(l): g.world.users[c] = User(c := l.accept(read_user))
def firstline(s): return s[:i] if (i := s.find('\n')) > 0 else s
def uerr(m):
    err(m)
    if u := g.world.thisuser: tsend(f'^r3internal error: {firstline(m)}')
def read_user(c):
    if not (u := g.world.users.get(c)) or not read_cxn(c): return
    b, h, e = c.rb, g.proto.phdr, 0
    while not e and len(b) >= h.size:
        i, n = h.unpack_from(b)
        if len(b) < (s := h.size + n - 1): break
        d, b = b[h.size:s], b[s:]
        try: u.ipq.append(decode_cp(u, i, d))
        except: e = traceback.format_exc()
    c.rb = b'' if e else b
    if e: return uerr(f'decode failed for client packet {i}\n{e}')
    with u: process_ipq(u)
def process_ipq(u):
    while u.ipq and u.ipq[0].ts + u.lat <= now():
        try: q, e = handle_packet(u, p := u.ipq.popleft()), 0
        except: e = traceback.format_exc()
        if e: uerr(f'handler failed for {p}\n{e}')
def handle_packet(u, p):
    dbg(f'{u} {p} {p.fields}')
    if not (h := globals().get(p.name)):
        x = f'\n{p.fields}' if p.fields is not None else '\n' + hexdump(p.data, prefix=' ') if p.data else ''
        err(f'no handler for {p}{x}')
    else: return h(u, p)
class Packet:
    __slots__ = 'ts ptype data name comment fields'.split()
    def __init__(p, i, d): p.ts, p.ptype, p.data, p.name, p.comment, p.fields = now(), i, d, 'unknown', '?', None
    __str__ = __repr__ = lambda p: f'Packet({p.ptype} {p.name} {p.comment} [{len(p.data)}])'
podsts = {k:struct.Struct('<'+k) for k in 'bBhHiIqQf'}
class DecodeError(RuntimeError): pass
class Decoder:
    __slots__ = 'b o'.split()
    def __init__(d, b): d.b, d.o = b, 0
    def fail(d, m): throw(DecodeError, f'{m} at offset {d.o} 0x{d.o:x} in\n{hexdump(d.b)}')
def decode_cp(u, i, b):
    p = Packet(i, b)
    if a := g.proto.ast_cp.get(i):
        p.name, p.comment = a.w[1], ' '.join(a.w[2:])
        try: p.fields = decode_fields(Decoder(b), a)
        except DecodeError: err(f'failed to decode {p}\n{traceback.format_exc()}')
    return p
def decode_fields(d, a): return {c.w[1]:decode_dtype(d, c) for c in a.body}
def decode_dtype(d, a):
    if s := podsts.get(k := a.w[0]): return decode_pod(d, s)
    if k not in 'sza': d.fail(f'unknown data type {k!r} for {a}')
    n = decode_count(d, a)
    if k in 'sz': return decode_bytes(d, n, k == 'z')
    return [decode_fields(d, a) for i in range(n)]
def decode_bytes(d, n, zstrip=0):
    if d.o + n > len(d.b): d.fail(f'insufficient bytes for size={n} remaining={len(d.b) - d.o}')
    r, d.o = d.b[d.o:d.o + n], d.o + n
    if zstrip: r = r.rstrip(b'\x00')
    return r
def decode_count(d, a):
    if len(a.w) < 3: return (len(d.b) - d.o) // calc_elemsize(d, a)
    if (c := a.w[2]).isnumeric(): return int(c)
    if c not in (v := 'BHI'): d.fail(f'invalid array count format {c!r}, expecting one of {v!r}')
    return decode_pod(d, podsts[c])
def calc_elemsize(d, a):
    if a.w[0] in 'sz': return 1
    if s := podsts.get(a.w[0]): return s.size
    if not a.body: d.fail('array has no fields')
    return sum(calc_elemsize(c) for c in a.body)
def decode_pod(d, s):
    if d.o + s.size > len(d.b): d.fail(f'not enough bytes to decode format={s.format} size={s.size} remaining={len(d.b) - d.o}')
    t, d.o = s.unpack_from(d.b, d.o), d.o + s.size
    return t[0] if len(t) == 1 else t
gs_kx = [w.split(',') for w in 'boots, cape,s helmet,s legs, neck,items shield,s shirt,s weapon,s'.split()]
gs_re = re.compile(r'<('+'|'.join(k for k,x in gs_kx)+r') [^>]*(?:type|color)="([^"]+)" [^>]*id="(\d+)"')
gs_fold = str.maketrans('éêè \'', 'eee__')
def merge_gearsyms(d):
    for k,x in gs_kx:
        r, s = {a.w[0]:a for a in d.get(k, [])}, set()
        for m in gs_re.finditer(slurp(p)) if exists(p := find_asset(pj('actor_defs', f'player_{k}{x}.xml'))) else err(f'no {k} symbols, file not found: {p}') or []:
            s.add(t := (t+'_'+m[3] if (t := m[2]) in s else t))
            n = t.strip().lower().translate(gs_fold)
            if (o := r.get(i := int(m[3]))) and o.ln: warn(f'duplicate {k} id {i} in "{p}": {t!r} {o}')
            r[i] = Ast('p_enum', 0, [i, n])
        d[k] = list(r.values())
    return d
class Protocol:
    __slots__ = 'netdefs desc ast_cp nametab_sp fctab fceo symtab enumtab'.split()
    phdr = struct.Struct('<BH')
    def setup(p, m=None):
        p.netdefs, p.desc, p.ast_cp = (d := merge_gearsyms(parse_mmc(slurp(g.opts.netdefs)))), progdesc(d), {a.w[0]:a for a in d['client_packet']}
        p.fceo = next((a.w[0] for a in d['fcolor'] if a.w[1] == 'encoding_offset'), 127)
        p.nametab_sp, p.fctab = {a.w[1]:a for a in d['server_packet']}, {a.w[1]:bytes((p.fceo+a.w[0],)) for a in d['fcolor'] if a.kind == 'p_enum' and a.w[1].startswith('c_')}
        p.symtab, p.enumtab = {a.w[1]:a.w[0] for v in d.values() for a in v if a.kind == 'p_enum'}, {k:{a.w[0]:a for a in l} for k,l in d.items()}
        return p
    def reload(p, o, m): p.setup(m)
class EncodeError(RuntimeError): pass
def encode_sp(n, d):
    a, b = (p := g.proto).nametab_sp.get(n), b''
    if not a: return err(f'fixme encode_sp {n!r} not in {p}')
    try: b, e = encode_fields(a, d), 0
    except EncodeError: e = traceback.format_exc()
    if e: return err(f'failed to encode packet {n!r} using {a}\n{e}')
    return p.phdr.pack(a.w[0], len(b) + 1) + b
def encode_fields(a, d):
    if not isinstance(d, dict): fail_enc(f'expecting dict not {type(d)} for {a}')
    return b''.join(encode_dtype(c, d.get(n, 0) if (n := c.w[1]).startswith('_') else d[n]) for c in a.body)
def fail_enc(m): throw(EncodeError, m)
def prep_arrsz(a, v):
    if len(a.w) < 3: return 0, b''
    if (c := a.w[2]).isnumeric(): return int(c), b''
    if c not in 'BHI': fail_enc(f'invalid count format {c!r} of {a}')
    return len(v), podsts[c].pack(len(v))
def encode_dtype(a, v):
    if s := podsts.get(k := a.w[0]): return s.pack(resolve_sym(v))
    if k not in 'sza': fail_enc(f'unknown data type {k!r} in {a}')
    n, r = prep_arrsz(a, v)
    if k in 'sz': 
        if not isinstance(v, bytes): v = v.encode('latin1')
        if n: v += b'\x00' * (n - len(v))
        if k == 'z' and not v.endswith(b'\x00'): v += b'\x00'
        r += v
    else:
        if not isinstance(v, list): fail_enc(f'expecting list not {type(v)} for {a}')
        r += b''.join(encode_fields(a, i) for i in v)
    return r    
def psend(n, user=None, **d):
    if not (u := user or g.world.thisuser).cxn or not (b := encode_sp(n, d)): return
    u.opq.append((now(), b, n, d))
    flush_opq(u)
def flush_opq(u):
    while u.opq and u.opq[0][0] + u.lat <= now():
        write_cxn(u.cxn, (t := u.opq.popleft())[1])
        dbg(f'flush_opq {u} {t[2]} {t[3]} = {t[1]} [{len(t[1])}]')
def encode_fcolor(fcname): return g.proto.fctab[fcname] if fcname else b''
fcmap = {b[0:1]:b[2:].decode() for b in b'r=red o=orange y=yellow g=green b=blue p=purple w=grey R=rose'.split()}
fcbpat = re.compile((fcspat := re.compile(r'\^\^|\^(['+''.join(chr(b[0]) for b in fcmap)+'])([1-4])')).pattern.encode())
def subfc(ft, b): return fcbpat.sub(lambda m: ft[f'c_{fcmap[m[1]]}{m[2].decode()}'] if m[1] else b'^', b)
def stripfc(s): return fcspat.sub(lambda m: '' if m[1] else '^', s)
def encode_fcstr(s): return subfc(g.proto.fctab, s.encode('latin1'))
def is_fcbyte(i): return (o := g.proto.fceo) <= i < o + len(g.proto.fctab)
def send_output(u, s, color='c_grey1', chan=3):
    if not u.cxn: return info(stripfc(s))
    for l in ((encode_fcolor(color) if not is_fcbyte((b := encode_fcstr(s))[0]) else b'') + b).split(b'\n'): psend('sp_output', channel=chan, text=l)
def tsend(s, user=None, chan=3): send_output(u := user or g.world.thisuser, s, color=None, chan=chan)
def cp_version(u, p):
    dbg(f'{u} sent {p} {p.fields}')
def cp_heartbeat(u, p): pass
def make_stats_dict(u):
    d = {a.w[1]:0 for a in g.proto.nametab_sp['sp_stats'].body}
    def seta(k, v): d[k+'_cur'], d[k+'_base'] = v, v
    for k in 'for agi int vol ins aur'.split(): seta(k, 6)
    for k in 'cour vita endu char reac perc rati dext ethe'.split(): seta(k, 8)
    for w in 'carry=200 hp=50 mp=40'.split(): seta((t := w.split('=', 1))[0], int(t[1]))
    for k in 'fab rec alc tot att def mag pot nec art ing'.split(): d[k+'_xp_next'] = 1000
    return d
def new_ent(i, **d):
    g.world.ents[i] = (e := Ent(i, **d))
    dbg(f'new ent {e}')
    return e
def cp_auth(u, p):
    psend('sp_sigils', sigils_bv=b'\xff\xff\xff\x07')
    psend('sp_buffs', buffs=[{'buff':255,'seconds':0} for i in range(10)])
    psend('sp_minute', minute=g.world.minute)
    psend('sp_clock', clock_ms=0)
    u.ent = (e := g.world.ents.get(1) or new_ent(1, map=get_map('1_trepont'), pos=V2(68,141)))
    psend('sp_control', ent=e.i)
    psend('sp_map', season=0, map_path=e.map.path)
    psend('sp_del_clime', seconds=255, clime=1)
    psend('sp_show_doodad', is_3d=1, is_visible=1, doodads=[])
    psend('sp_show_beamin', x=e.pos.x, y=e.pos.y)
    psend('sp_items', items=[])
    psend('sp_stats', **make_stats_dict(u))
    psend('sp_known', known_bv=b'\x00'*64)
    psend('sp_ping', echo_sdata=b'1234')
    psend('sp_auth')
    psend_visible_ents(u)
def cp_need_srvinfo(u, p): tsend(f'{g.proto.desc}')
def match_sym(k, s):
    if (d := g.proto.netdefs[k]) and (i := next((a.w[0] for a in d if a.w[1] == s), None)) is not None: return s,i
    if len(l := [(n,a.w[0]) for a in d if (n := a.w[1]).startswith(s)]) > 1: throw(MatchError, 'ambiguous: '+' '.join(f'{i}:{n}' for n,i in l))
    return l[0] if l else throw(MatchError, f'no match for symbol {s!r} in enum {k}')
def get_sym(k, i, d='unknown'): return a.w[1] if (a := g.proto.enumtab[k].get(i)) else d
def fmt_sym(k, v): return f'{k}:{v}={get_sym(k, v)}'
def fmt_attrsym(o, k): return fmt_sym(k, getattr(o, k))
def resolve_sym(v): return g.proto.symtab[v] if isinstance(v, str) else v
class Ent:
    __slots__ = 'i name pos map model frame rotation health max_health control bling title'.split()
    def __init__(e, i, **d):
        v = {'i':i, 'map':(m := d.get('map', g.world.maps[0])), 'pos':m.startpos + V2(i,0), 'name':f'ent{i}', 'control':1, 'model':(mo := d.get('model', 0)), 'bling':Bling() if get_model(mo).has_bling else None, 'health':10, 'max_health':d.get('health', 10), 'title':''}
        for k in e.__slots__: setattr(e, k, d.get(k, v.get(k, 0)))
    __str__ = __repr__ = lambda e: f'e{e.i} {e.name!r} {fmt_attrsym(e, "model")} @m{e.map.i}:{e.pos}'
def can_bling(e): return e.bling and get_model(e.model).has_bling
def none_bling(k): return g.proto.symtab.get(k + '_none', next((i for i,a in g.proto.enumtab[k].items() if a.w[1].lower() == 'none'), 0))
class Bling:
    __slots__ = 'skin hair shirt legs boots head shield weapon cape helmet'.split()
    def __init__(b, **d): any(setattr(b, k, d.get(k, none_bling(k))) for k in b.__slots__)
def attrdict(o, s=None): return {k:getattr(o, k) for k in (s.split() if s else o.__slots__)} if o else {}
def psend_visible_ents(u): any(psend_ent(u, o) for o in g.world.ents.values() if o.map == e.map and distsq(o.pos, e.pos) < 625) if (e := u.ent) else 0
def psend_ent(u, e):
    psend('sp_set_ent_with_bling' if can_bling(e) else 'sp_set_ent', ent=e.i, x11_buffs0_4=e.pos.x, y11_buffs5_9=e.pos.y, buffs10_25=0, **attrdict(e, 'rotation model frame max_health health control name'), **attrdict(e.bling), extra='')
    if e.title: psend('sp_title_ent', ent=e.i, title=e.title)
def dispatch_ucmd(u, c, a):
    try: (f := match_prefix(globals(), c, 'ucmd_', what='command')[1])((setattr(u, 'thiscmd', f), u)[1], a)
    except (MatchError, ArgError) as e: return tsend(f'^r2{e}')
def ucmd_dev(u, a):
    if a: u.dev = arg_bool(a[0])
    tsend(f'{u}.dev = {u.dev}')
listables = {
    'ucmds':lambda: [c[5:] for c in globals() if c.startswith('ucmd_')],
    'enums':lambda: [k for k in g.proto.netdefs if k],
    'maps':lambda: [f'^b1{m.i:03d} ^y3{m.name}' for m in g.world.maps.values()],
    'items':lambda: [f'^b1{i.i:04d} ^y3{i.name}' for i in g.world.items.values()],
    'colors':lambda: [f'{i:02d} ^{chr(k[0])}{j}^^{chr(k[0])}{j} {n}' for k,v in fcmap.items() for j in range(1,5) if (i := g.proto.symtab.get(n := f'c_{v}{j}')) is not None],
    'levels':lambda: [f'^b1{i:03d} ^y3{e:10d} ^g2+{e - levels[i-1] if i else 0}' for i,e in enumerate(levels)],
}
def ucmd_list(u, a):
    if not a: return usage()
    f = (lambda t: a[1] in t) if len(a) > 1 else lambda t: 1
    (d := listables.copy()).update(g.proto.enumtab)
    w, l = match_prefix(d, a[0], what='list')
    if callable(l): l = l()
    if not (r := [f'^b2{i} ^o2{v}' for i,a in l.items() if f(v := a.w[1])] if (is_enum := isinstance(l, dict)) else sorted(f'^o2{k}' for k in l if f(k))): return tsend(f'^r1no match for ^y1{a[1]!r}^r1 in ^g1{w}' if len(a) > 1 else f'^r1no such list: ^y1{a[0]}')
    tsend(f'^g1matches in {w}: [{len(r)}]' + (x := '\n' if is_enum or len(r) > 3 else ' ') + x.join(r))
ucmd_list.__doc__ = f'({" | ".join(listables)} | enum_name) [filter_substr]'
def match_attr(o, s):
    if hasattr(o, s): return s
    if len(l := [k for k in o.__slots__ if k.startswith(s)]) > 1: throw(MatchError, 'ambiguous: '+' '.join(l))
    return l[0] if l else throw(MatchError, f'no such attribute {s!r} in {o.__class__.__name__} (expecting one of {" ".join(k for k in o.__slots__ if globals().get("arg_"+type(getattr(o, k)).__name__.lower()))})')
def place_ent(e, m, p):
    e.map = m
    occupied = set(o.pos for o in g.world.ents.values() if o.map == m and o != e)
    e.pos = min(l, key=lambda t: t[1])[0] if (l := [t for t in walkables(m, p, 5) if t[0] not in occupied]) else p
def ucmd_ent(u, a):
    'ent_id - create or switch control'
    if a:
        if not (e := g.world.ents.get(i := arg_int(a[0]))):
            e = new_ent(i)
            if o := u.ent: place_ent(e, o.map, o.pos)
        u.ent = e
        psend('sp_clear_ents')
        psend('sp_control', ent=e.i)
        psend_visible_ents(u)
    tsend(f'{u}.ent = {u.ent}')
def get_ent(u): return e if (e := u.ent) else throw(ArgError, 'no ent')
def ucmd_name(u, a):
    if (e := get_ent(u)) and a:
        e.name = ' '.join(a)
        resend_ent(u)
    tsend(f'e{e.i}.name = {e.name}')
def ucmd_title(u, a):
    (e := get_ent(u)).title = ' '.join(a)
    psend('sp_title_ent', ent=e.i, title=e.title)
    tsend(f'e{e.i}.title = {e.title}')
def arg_sym(k, a, ci, p=None): return (get_sym(k, i := int(a[0])), i) if a and a[0].isdigit() else match_sym(k, a[0] if p and a[0].startswith(p) else p+a[0] if p else a[0]) if a else (get_sym(k, ci), ci)
def resend_ent(u):
    psend('sp_del_ent', ent=u.ent.i)
    psend_ent(u, u.ent)
def arg_entattr(u, k, a, p=None):
    n, i = arg_sym(k, a, getattr(e := get_ent(u), k), p)
    if i != getattr(e, k):
        setattr(e, k, i)
        resend_ent(u)
    tsend(f'e{e.i}.{k} = {i} {n}')
def ucmd_model(u, a): arg_entattr(u, 'model', a)
def ucmd_frame(u, a): arg_entattr(u, 'frame', a, 'frame_')
def ucmd_action(u, a):
    n, i = arg_sym(k := 'action', a, 0)
    psend('sp_move_ent', ent=(e := get_ent(u)).i, action=i)
    tsend(f'e{e.i} {k}:{i} {n}')
def match_substr(l, s, key=None):
    if (f := key or (lambda v:v)) and (t := next((v for v in l if f(v) == s), None)): return t
    if len(t := [v for v in l if s in f(v)]) > 1: throw(MatchError, 'ambiguous: '+' '.join(str(v) for v in t))
    if not t: throw(MatchError, f'no match for {s!r}')
    return t[0]
def ucmd_item(u, a):
    'position quantity item_id_or_substr - change inventory contents'
    if not (len(a) == 3 or (len(a) == 2 and a[1] == '0')): return usage()
    if not (d := g.world.items): return tsend('no items defined')
    if not (0 <= (p := arg_int(a[0])) <= (m := 43)): return tsend(f'^r3invalid position, expecting 0..{m}')
    if not (0 <= (q := arg_int(a[1])) <= (m := 1e9)): return tsend(f'^r3invalid quantity, expecting 0..{m}')
    if not q: return psend('sp_del_item', ipos=p)
    if not (i := d.get(int(s)) if (s := a[2]).isdigit() else match_substr(d.values(), s, key=lambda i:i.name)): return tsend(f'^r3no such item: {s}')
    psend('sp_set_item', image=i.image, quantity=q, ipos=p, iflags=255, item=i.i)
    tsend(f'item @ {p} = {q} {i.i}:{i.name}')
class ArgError(ValueError): pass
def arg_bool(s): return s.lower() not in ('', '0', 'n', 'no', 'off', 'f', 'false', 'disable')
def arg_int(s): return int(s) if s.isdigit() or (s.startswith('-') and s[1:].isdigit()) else throw(ArgError, f'expecting integer, not {s!r}')
def arg_map(s): return (g.world.maps.get(int(s)) or throw(ArgError, f'invalid map: {s}')) if s.isdigit() else match_prefix(g.world.nametab_maps, s, what='map', fmt=lambda t:f'^y2{t[1].i}^w3:^g2{t[1].name}')[1]
def arg_v2(s): return V2(int(v) for v in l) if len(l := s.split(',', 1)) == 2 and all(v.isdigit() for v in l) else throw(ArgError, f'invalid x,y {s!r}')
def usage(): tsend(f'^r1usage: {n[5:] if (n := (f := g.world.thisuser.thiscmd).__name__)[1:5] == "cmd_" else n} {f.__doc__ or f"(see {f.__name__})"}')
def walkables(m, p, r):
    if not (h := get_heights(m)): return [(p, 0)]
    a, b = h.clampv(p - r), h.clampv(p + r)
    return [(v, distsq(p, v)) for y in range(a.y, b.y+1) for x in range(a.x, b.x+1) if h[v := V2(x,y)]]
def find_walkable(m, p):
    if not (h := get_heights(m)) or (h.contains(p) and h[p]): return p
    if l := walkables(m, p, 25): return min(l, key=lambda t: t[1])[0]
    return next((v for y in range(h.y) for x in range(h.x) if h[v := V2(x,y)]), p)
def set_pos(u, p, m=None):
    e = u.ent
    if map_changed := (m and e.map != m): e.map = m
    e.pos = find_walkable(e.map, p)
    psend('sp_set_spell', spell_result=5, spell=46, srdata=b'\x00')
    psend('sp_move_ent', ent=e.i, action=27)
    psend('sp_clear_ents')
    if map_changed: psend('sp_map', season=0, map_path=m.path)
    psend_visible_ents(u)
    psend('sp_set_spell', spell_result=1, spell=46, srdata=b'\x00')
def ucmd_map(u, a):
    'map_id | map_name'
    set_pos(u, get_ent(u).pos, arg_map(a[0])) if a else usage()
def ucmd_teleport(u, a):
    'x,y | map | map x,y'
    if (e := get_ent(u)) and len(a) > 1: m, p = arg_map(a[0]), arg_v2(a[1])
    elif a and ',' in a[0]: m, p = e.map, arg_v2(a[0])
    elif a: m, p = arg_map(a[0]), e.pos
    else: return usage()
    set_pos(u, p, m)
def ucmd_help(u, a):
    if not (l := list_funcdocs(p := 'ucmd_', a[0] if a else None)): return tsend(f'^r3no such command {a[0]!r}' if a else f'^r3no commands')
    m = max(len(n) for n,d in l)
    for n,d in l: tsend(f'^g1{n}{(m - len(n))*" "} {"^g3" if d else "^y3"}{d or p+n}')
def ucmd_rotation(u, a):
    '0..7 - north clockwise'
    if (e := get_ent(u)) and a: e.rotation = 45*(r := arg_int(a[0]) % 8, psend('sp_move_ent', ent=e.i, action=38 + r))[0]
    tsend(f'e{e.i}.rotation = {e.rotation}')
def ucmd_say(u, a):
    e, b = get_ent(u), encode_fcstr(f'^w1{u.ent.name}: ^y1{" ".join(a)}')
    any(psend('sp_output', user=o, text=b, channel=0) for o in g.world.users.values() if o.ent and o.ent.map == e.map and distsq(o.ent.pos, e.pos) < 625)
def ucmd_wear(u, a):
    '(worn | body_part) [value] - change gear/body (-1 removes)'
    if not can_bling(e := get_ent(u)): return tsend('invalid model')
    if not a: return usage()
    k = match_attr(e.bling, a[0])
    wi = next((a.w[0] for a in g.proto.netdefs['worn'] if a.w[1] == k), None)
    if len(a) > 1:
        if a[1] in ('-1', 'no', 'none'): n, i = None, none_bling(k)
        elif a[1].isdigit(): n = get_sym(k, i := int(a[1]))
        else: n, i = match_sym(k, a[1])
        setattr(e.bling, k, i)
        if wi:
            psend('sp_del_worn', ent=e.i, worn=wi)
            psend('sp_set_worn', ent=e.i, worn=wi, gear=i)
        else: resend_ent(u)
    else: n = get_sym(k, i := getattr(e.bling, k))
    tsend(f'e{e.i}.bling.{k} = {i} {n}')
def ucmd_minute(u, a):
    if a:
        g.world.minute = (m := arg_int(a[0]) % 360)
        psend('sp_minute', minute=m)
    tsend(f'minute = {g.world.minute}')
def psend_stat(i, v): psend('sp_set_stat' if v < 1<<31 else 'sp_set_stat64', stat=i, value=v)
def ucmd_stat(u, a):
    'stat-id value'
    if len(a) < 2: return usage()
    (n, i), v = ('', arg_int(s)) if (s := a[0]).isdigit() else match_sym('stat', s), arg_int(a[1])
    psend_stat(i, v)
def gen_levels():
    m = [v for s,e,v in ((0,20,1.2),(21,90,1.1),(91,98,1.6),(99,100,1.7)) for i in range(s,e+1)]
    e = (t := [0,440,728] + [0]*98)[2]
    for i in range(3,101): t[i] = (e := int(e + m[i]*(e - t[i - 2])))
    return t
levels = gen_levels()
skills = {(a := w.split('='))[0]:a[1] for w in 'fab=man rec=harv alc=alch tot=ovrl def=def att=att mag=mag pot=pot nec=sum art=cra ing=eng'.split()}
def ucmd_xp(u, a):
    'skill xp|Ln'
    if len(a) < 2: return usage()
    if a[0].isdigit(): n = get_sym('stat', i := int(a[0]))
    elif a[0][0].islower():
        k = match_prefix(skills, w := a[0].replace('é','e'), what='skill')[1]
        i = resolve_sym(n := f'{k}_exp'.upper())
    else: n, i = match_sym(a[0], 'stat')
    if not n.endswith('_EXP'): throw(ArgError, f'not a skill exp stat: {a[0]!r} = {i} {n}')
    m = len(levels) - 1
    v = levels[l := clamp(0, int(a[1][1:]), m)] if a[1][0] == 'L' else (v := int(a[1]), l := next((j for j,e in enumerate(levels[:-1]) if e <= v < levels[j+1]), m))[0]
    psend_stat(i, v)
    psend_stat(i + 1, levels[l+1] if l < m else levels[-1])
    any(psend_stat(resolve_sym(n[:-4]+'_S_'+x), l) for x in ('CUR','BASE'))
def cp_input(u, p):
    if not (a := (t := p.fields['text'].decode('latin1')).split()): return
    if (o := t[0] in '#&') or u.dev: return dispatch_ucmd(u, a[0][o:], a[1:])
    ucmd_say(u, [t])
def cp_look_doodad(u, p): tsend(f'{p.name} {p.fields["doodad"]}')
def cp_walk(u, p): set_pos(u, V2(p.fields[k] for k in 'xy'))
def cp_look_ent(u, p): tsend(f'{p.name} {p.fields["ent"]}')
def cp_use_doodad(u, p): tsend(f'{p.name} {p.fields["doodad"]}')
def cp_turn_left(u, p):
    psend('sp_move_ent', ent=(e := u.ent).i, action='turn_left')
    e.rotation = (e.rotation + 45) % 360
def cp_turn_right(u, p):
    psend('sp_move_ent', ent=(e := u.ent).i, action='turn_right')
    e.rotation = (e.rotation - 45) % 360
def cp_need_spell(u, p): psend('sp_set_spell', spell_result='sr_nameinfo', spell=(i := p.fields['spell']), srdata=f'spell{i}\x00')
def update():
    w, rs, mh = g.world, g.net.rs, g.manhole
    for c in list(w.users.keys()):
        if c not in rs: del w.users[c]
    for u in w.users.values():
        with u: process_ipq(u)
        flush_opq(u)
    for c in list(mh.rcons.keys()):
        if c not in rs: del mh.rcons[c]
class Clock:
    __slots__ = 'fps t0 dt nf'.split()
    def __init__(c): c.fps, c.t0, c.dt, c.nf = (0,)*4
    def tick(c):
        if (f := g.opts.fps) != c.fps: c.dt, c.fps, c.t0, c.nf = 1.0 / f, f, now(), 0
        c.nf += 1
        return c.t0 + c.dt*c.nf
def run():
    while 1:
        ts_next = g.clock.tick()
        update()
        while 1:
            t_poll = max(0, ts_next - now())
            r, w, _ = select.select(g.net.rs, g.net.ws, [], t_poll)
            for c in r: c.rh(c)
            for c in w: write_cxn(c, flush=1)
            if now() >= ts_next: break
def main():
    global g
    g, a = G(), (p := argparse.ArgumentParser(description='test server')).add_argument
    a('-a', '--assetdirs', metavar='paths', type=lambda s: s.split(';'), default='.', help='semicolon separated list searched in order')
    a('-d', '--debug', action='store_true', help='log level debug')
    a('-f', '--fps', metavar='int', type=int, default=30, help='updates per second')
    a('-i', '--initmmc', metavar='path', help=f'read opts and commands from file ({default_initmmc})')
    a('-l', '--latency', metavar='ms', type=int, default=0, help='simulated packet one-way trip delay in milliseconds')
    a('-n', '--netdefs', metavar='path', default=default_netdefs, help=f'network protocol definitions ({default_netdefs})')
    a('-r', '--rcon', metavar='port', type=int, default=56000, help='remote console server port')
    a('-t', '--termcolors', metavar='yes|no|auto', default='auto', help='ansi terminal color escape codes in console messages', type=lambda s: (e := os.environ).get('COLORTERM') or 'color' in e.get('TERM', '') if s[0] in 'am?' else s[0] in 'y1')
    a('-w', '--world', metavar='port', type=int, default=6000, help='game world server port')
    f, g.opts = default_initmmc if (i := (o := p.parse_args()).initmmc) is None else i, o
    logging.basicConfig(datefmt='%H:%M:%S', format='%(asctime)s.%(msecs)03d %(message)s', level='DEBUG', stream=sys.stdout)
    if l := (d := (parse_mmc(slurp(f)) if i is not None or exists(f) else {})).get('opts'): p.set_defaults(**{a.w[0]:(arg_bool(a.w[1]) if isinstance(getattr(o, a.w[0], None), bool) else ' '.join(a.w[1:])) for a in l})
    g.opts = (o := p.parse_args() if l else o)
    logging.getLogger().setLevel('DEBUG' if o.debug else 'INFO')
    g.net, g.manhole, g.proto, g.world, g.clock = Net(), (m := Manhole()), Protocol().setup(), (w := World()), Clock()
    if p := o.rcon: m.setup().listen(p, accept_rcon)
    w.setup().listen(o.world, accept_user)
    with User(0) as u: [dispatch_ucmd(u, a.w[0], a.w[1:]) for a in d.get('commands', {})]
    try: run()
    except KeyboardInterrupt: print('')
    info('quit')
if __name__ == '__main__': main()
