"""A tiny 9P2000.L server of a tree in memory, for the mesh tests'
served anchors.

    python3 -I tiny9p.py <socket>

Serves /hello.txt, /dir/inner.txt and /clock (the time now, each read, and QTTMP),
and lets files be written and made. With SLOW set, each read of /clock
takes 5s.
"""
import os, socket, struct, sys, threading, time

path = sys.argv[1]
nodes = {1: ("dir", {"hello.txt": 2, "dir": 3, "clock": 5}, 1)}
nodes[2] = ("file", bytearray(b"hello from a server\n"), 1)
nodes[3] = ("dir", {"inner.txt": 4}, 1)
nodes[4] = ("file", bytearray(b"inner\n"), 3)
nodes[5] = ("clock", None, 1)
nxt = [6]
lock = threading.Lock()
import contextlib
NOLOCK = contextlib.nullcontext()


def s(b):
    return struct.pack("<H", len(b)) + b


def qid(n):
    kind = nodes[n][0]
    # The clock's never the same, so it's left out of what's kept
    return struct.pack("<BIQ", {"dir": 0x80, "clock": 0x04}.get(kind, 0), 0, n)


def data(n):
    kind, body, _ = nodes[n]
    if kind == "clock" and os.environ.get("SLOW"):
        time.sleep(5)
    return time.strftime("%H:%M:%S\n").encode() if kind == "clock" else bytes(body)


def serve(conn):
    fids = {}

    def recv(k):
        b = b""
        while len(b) < k:
            chunk = conn.recv(k - len(b))
            if not chunk:
                raise EOFError
            b += chunk
        return b

    while True:
        try:
            size, = struct.unpack("<I", recv(4))
            body = recv(size - 4)
        except EOFError:
            return
        t, tag = struct.unpack("<BH", body[:3])
        m = body[3:]

        def reply(rt, payload=b""):
            conn.sendall(struct.pack("<IBH", 7 + len(payload), rt, tag) + payload)

        def err(code):
            reply(7, struct.pack("<I", code))

        with (lock if t not in (116, 24, 110, 12, 120) else NOLOCK):
            try:
                if t == 100:
                    msize, = struct.unpack("<I", m[:4])
                    reply(101, struct.pack("<I", min(msize, 65536)) + s(b"9P2000.L"))
                elif t == 104:
                    fid, = struct.unpack("<I", m[:4])
                    fids[fid] = 1
                    reply(105, qid(1))
                elif t == 110:
                    fid, newfid, n = struct.unpack("<IIH", m[:10])
                    off, at, qs = 10, fids[fid], []
                    for _ in range(n):
                        l, = struct.unpack("<H", m[off:off + 2])
                        name = m[off + 2:off + 2 + l].decode()
                        off += 2 + l
                        kind, body2, parent = nodes[at]
                        nxtn = parent if name == ".." else body2.get(name) if kind == "dir" else None
                        if nxtn is None:
                            break
                        at = nxtn
                        qs.append(qid(at))
                    if n and not qs:
                        err(2)
                        continue
                    if len(qs) == n:
                        fids[newfid] = at
                    reply(111, struct.pack("<H", len(qs)) + b"".join(qs))
                elif t == 24:
                    fid, = struct.unpack("<I", m[:4])
                    n = fids[fid]
                    kind = nodes[n][0]
                    mode = 0o40755 if kind == "dir" else 0o100644
                    size = len(data(n)) if kind != "dir" else 0
                    now = int(time.time())
                    reply(25, struct.pack("<Q", 0x7ff) + qid(n) + struct.pack("<IIIQQQQQ", mode, os.getuid(), os.getgid(), 1, 0, size, 4096, 1)
                          + struct.pack("<QQQQQQQQ", now, 0, now, 0, now, 0, 0, 0) + struct.pack("<QQ", 0, 0))
                elif t == 12:
                    fid, = struct.unpack("<I", m[:4])
                    reply(13, qid(fids[fid]) + struct.pack("<I", 0))
                elif t == 116:
                    fid, off, count = struct.unpack("<IQI", m[:16])
                    d = data(fids[fid])[off:off + count]
                    reply(117, struct.pack("<I", len(d)) + d)
                elif t == 118:
                    fid, off, count = struct.unpack("<IQI", m[:16])
                    d = m[16:16 + count]
                    body2 = nodes[fids[fid]][1]
                    if len(body2) < off + len(d):
                        body2.extend(b"\0" * (off + len(d) - len(body2)))
                    body2[off:off + len(d)] = d
                    reply(119, struct.pack("<I", len(d)))
                elif t == 40:
                    fid, off, count = struct.unpack("<IQI", m[:16])
                    entries = list(nodes[fids[fid]][1].items())[off:]
                    out = b""
                    for i, (name, n) in enumerate(entries, start=off + 1):
                        e = qid(n) + struct.pack("<QB", i, 4 if nodes[n][0] == "dir" else 8) + s(name.encode())
                        if len(out) + len(e) > count:
                            break
                        out += e
                    reply(41, struct.pack("<I", len(out)) + out)
                elif t == 14:
                    fid, = struct.unpack("<I", m[:4])
                    l, = struct.unpack("<H", m[4:6])
                    name = m[6:6 + l].decode()
                    n = nxt[0]
                    nxt[0] += 1
                    nodes[n] = ("file", bytearray(), fids[fid])
                    nodes[fids[fid]][1][name] = n
                    fids[fid] = n
                    reply(15, qid(n) + struct.pack("<I", 0))
                elif t == 26:
                    fid, valid = struct.unpack("<II", m[:8])
                    if valid & 8:
                        size, = struct.unpack("<Q", m[20:28])
                        del nodes[fids[fid]][1][size:]
                    reply(27)
                elif t == 50:
                    reply(51)
                elif t == 120:
                    fid, = struct.unpack("<I", m[:4])
                    fids.pop(fid, None)
                    reply(121)
                elif t == 108:
                    reply(109)
                else:
                    err(95)
            except (KeyError, TypeError):
                err(5)


if os.path.exists(path):
    os.unlink(path)
srv = socket.socket(socket.AF_UNIX)
srv.bind(path)
srv.listen()
print("listening", flush=True)
while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
