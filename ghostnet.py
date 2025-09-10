#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GhostNet — Kali-only, single-file, stdlib-only operational proxy shell
Author: Kranidiotis Nikolaos

FEATURES
- Local SOCKS5 on localhost that forwards through a selected chain (SOCKS5 / HTTP CONNECT [+ TLS] / Tor / direct)
- Per-terminal, environment-scoped proxying (no system changes). Branded prompt:
    GHOSTNET(root)[ /dir ] >
- Always-on kill-switch (watchdog: consecutive failures OR RTT spike)
- Proxies TXT → inventory JSON → active chain JSON lifecycle
- Diagnostics: bench, scoring, auto-pick best N hops (writes active_chain.json)
- Exec mode: run one command fully proxied, return real exit code
- Tor integration: auto-detect SOCKS, optional ControlPort (NEWNYM), optional per-stream isolation via SOCKS auth
- Zero external binaries; Python 3.9+ stdlib only

QUICKSTART
1) Seed proxies:
   # proxies.txt (examples)
   # socks5://user:pass@203.0.113.5:1080?rdns=1
   # http://proxy.corp:8080
   # https://proxy.corp:443        # HTTP CONNECT over TLS
   # tor                           # alias for socks5://127.0.0.1:9050?rdns=1

2) Build/merge inventory:
   python3 ghostnet.py --init

3) Diagnose & select (single hop or chain):
   python3 ghostnet.py --diagnostics              # best 1
   python3 ghostnet.py --diagnostics --chain-size 3

4) Start a proxied shell (uses active_chain.json):
   python3 ghostnet.py --start
   # or: --exec -- <cmd ...>
   python3 ghostnet.py --exec -- curl https://ifconfig.me

TOR MODES
  --tor-mode {off,prefer,require}   (default: prefer)
  --tor-socks HOST:PORT             (default: 127.0.0.1:9050)
  --tor-control HOST:PORT           (optional; e.g., 127.0.0.1:9051)
  --tor-password STRING             (optional for control)
  --tor-isolate                     (per-connection SOCKS auth for Tor stream isolation)
  --tor-newnym-on-start             (send NEWNYM if control available)
  --tor-newnym-interval SEC         (periodic NEWNYM)

NOTES
- Tools that honor env proxies (curl, git, pip, apt) are fully covered.
- Apps that ignore proxies aren’t force-routed (by design, no iptables/LD_PRELOAD).
- The watchdog kills the session on failure/spike to avoid leaks.
"""

import argparse, copy, json, os, socket, ssl, struct, sys, threading, time, select, errno, traceback, shlex, subprocess, pty, fcntl, termios, re, secrets
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed


HTTPS_PROXY_PORTS = {443, 8443, 9443, 10443}
# -------------------- Utilities --------------------

def parse_hostport(s, default_host='127.0.0.1', default_port=0):
    if not s: return (default_host, default_port)
    if isinstance(s, tuple): return s
    if ':' in s:
        h, p = s.rsplit(':', 1)
        try: return (h, int(p))
        except: return (h, default_port)
    return (s, default_port)

def set_nonblock(fd):
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

def now_ms():
    return int(time.time()*1000)

def load_json(path, default):
    try:
        with open(path,"r",encoding="utf-8") as f: return json.load(f)
    except: return default

def save_json(path, obj):
    with open(path,"w",encoding="utf-8") as f: json.dump(obj, f, indent=2, sort_keys=True)

def _render_progress(done, total, width=40, prefix="[diagnostics]"):
    total = max(total, 1)
    frac = min(max(done / total, 0.0), 1.0)
    fill = int(frac * width)
    bar = "█" * fill + "·" * (width - fill)
    sys.stdout.write(f"\r{prefix} [{bar}] {done}/{total}")
    sys.stdout.flush()
    if done >= total:
        sys.stdout.write("\n")
        sys.stdout.flush()


# -------------------- TXT -> Inventory --------------------

def parse_line_url(line):
    m = re.split(r"#", line, 1)
    left = m[0].strip(); notes = (m[1].strip() if len(m)>1 else "")
    if not left: return None
    u = urlparse(left)
    p = {
        "type": (u.scheme or "").lower(),
        "host": u.hostname,
        "port": u.port,
        "username": u.username or None,
        "password": u.password or None,
        "tls": False,
        "remote_dns": True,  # default on for socks-like
        "notes": notes
    }
    q = parse_qs(u.query or "")
    if "tls" in q: p["tls"] = q["tls"][0].lower() in ("1","true","yes","on")
    if "rdns" in q: p["remote_dns"] = q["rdns"][0].lower() in ("1","true","yes","on")
    if p["type"] == "https":  # https proxy = http CONNECT over TLS
        p["type"] = "http"; p["tls"] = True
    return p

def parse_line_space(line):
    m = re.split(r"#", line, 1)
    left = m[0].strip(); notes = (m[1].strip() if len(m)>1 else "")
    if not left: return None
    parts = left.split()
    if len(parts) < 1: return None
    # "tor" alias
    if parts[0].lower() == "tor":
        return {"type":"tor","host":"127.0.0.1","port":9050,"username":None,"password":None,"tls":False,"remote_dns":True,"notes":"tor"}
    if len(parts) < 3: return None
    p = {
        "type": parts[0].lower(),
        "host": parts[1],
        "port": int(parts[2]),
        "username": None,
        "password": None,
        "tls": False,
        "remote_dns": True,
        "notes": notes
    }
    idx = 3
    if idx < len(parts) and "=" not in parts[idx]:
        p["username"] = parts[idx]; idx += 1
    if idx < len(parts) and "=" not in parts[idx]:
        p["password"] = parts[idx]; idx += 1
    for k in parts[idx:]:
        if "=" in k:
            k0,v0 = k.split("=",1)
            if k0=="tls": p["tls"] = v0.lower() in ("1","true","yes","on")
            if k0 in ("rdns","remote_dns"): p["remote_dns"] = v0.lower() in ("1","true","yes","on")
    return p

def parse_line_bare(line):
    # Accept "host:port" -> HTTP CONNECT proxy
    # Auto-mark TLS if port looks like HTTPS proxy port.
    m = re.match(r'^\s*([^:#\s]+):(\d+)\s*$', line)
    if not m:
        return None
    host, port = m.group(1), int(m.group(2))
    return {
        "type": "http",                 # stored as http-type proxy
        "host": host,
        "port": port,
        "username": None,
        "password": None,
        "tls": (port in HTTPS_PROXY_PORTS),  # auto TLS on known HTTPS proxy ports
        "remote_dns": True,
        "notes": ""
    }


def parse_proxies_txt(path):
    out = []
    with open(path,"r",encoding="utf-8") as f:
        for raw in f:
            s = raw.strip()
            if not s or s.startswith("#"): continue
            if "://" in s:
                p = parse_line_url(s)
            else:
                p = parse_line_space(s) or parse_line_bare(s)
            if p:
                t = p["type"]
                if t not in ("socks5","http","direct","tor"):
                    if t == "socks": p["type"] = "socks5"
                    elif t == "https": p["type"] = "http"; p["tls"] = True
                    else: continue
                out.append(p)
    return out


def merge_inventory(old, new_list):
    # old = {"proxies":[{...}], "version":1}
    by_key = {}
    def key(p): return (p["type"], p["host"], int(p["port"]), p.get("username") or "", bool(p.get("tls",False)))
    for p in old.get("proxies", []):
        by_key[key(p)] = p
    merged = []
    counter = 1
    for p in new_list:
        k = key(p)
        if k in by_key:
            cur = by_key[k]
            if p.get("notes"): cur["notes"] = p["notes"]
            cur["remote_dns"] = bool(p.get("remote_dns", cur.get("remote_dns", True)))
            merged.append(cur)
        else:
            p = dict(p)  # copy
            p["id"] = f"px-{counter:05d}"; counter += 1
            p["metrics"] = {}
            merged.append(p)
    return {"version":1, "updated": int(time.time()), "proxies": merged}

# -------------------- Chain dialer --------------------

class ChainClient:
    """
    Build a TCP stream to final_host:final_port through a sequence of hops:
      hop.type in {"socks5","http","tor","direct"}
      hop.tls (for http CONNECT over TLS)
      hop.remote_dns (for socks5 domain mode)
    The dialer performs successive CONNECTs so that a single socket 's' becomes a tunnel to the final destination.
    """
    def __init__(self, chain):
        self.hops = chain.get("hops", [])
        self.timeout = chain.get("timeout", 10)
        self.ssl_ctx = ssl.create_default_context()
        self.chain = chain  # retained for per-conn cloning, etc.
        self.tor_isolate = False  # may be set by caller

    def _tcp_connect(self, host, port, timeout):
        s = socket.create_connection((host, port), timeout=timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return s

    def _wrap_tls(self, sock, server_hostname):
        return self.ssl_ctx.wrap_socket(sock, server_hostname=server_hostname)

    def _socks5_handshake(self, s, username=None, password=None):
        # greeting
        methods = [0x00] if not username else [0x02]
        s.sendall(struct.pack("!BBB", 0x05, len(methods), *methods))
        resp = s.recv(2)
        if len(resp) < 2 or resp[0] != 0x05:
            raise OSError("SOCKS5: bad greeting")
        method = resp[1]
        if method == 0xFF:
            raise OSError("SOCKS5: no acceptable auth")
        if method == 0x02:
            u = (username or "").encode()
            p = (password or "").encode()
            pkt = b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p
            s.sendall(pkt)
            a = s.recv(2)
            if len(a) < 2 or a[1] != 0x00:
                raise OSError("SOCKS5: auth failed")
        return s

    def _socks5_connect(self, s, host, port, remote_dns=True, username=None, password=None):
        self._socks5_handshake(s, username, password)
        if remote_dns:
            hb = host.encode()
            req = b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack("!H", port)
        else:
            ip = socket.gethostbyname(host)
            req = b"\x05\x01\x00\x01" + socket.inet_aton(ip) + struct.pack("!H", port)
        s.sendall(req)
        resp = s.recv(4)
        if len(resp) < 4 or resp[1] != 0x00:
            raise OSError("SOCKS5: connect failed")
        atyp = s.recv(1)[0]
        if atyp == 0x01: _ = s.recv(4)
        elif atyp == 0x03: l = s.recv(1)[0]; _ = s.recv(l)
        elif atyp == 0x04: _ = s.recv(16)
        _ = s.recv(2)
        return s

    def _http_connect(self, s, host, port, tls=False):
        if tls:
            s = self._wrap_tls(s, server_hostname=host)
        req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: keep-alive\r\n\r\n".encode()
        s.sendall(req)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 65536:
                break
        status = buf.split(b"\r\n",1)[0]
        if b" 200 " not in status:
            raise OSError("HTTP CONNECT failed")
        return s

    def dial(self, final_host, final_port):
        hops = copy.deepcopy(self.hops)
        # Normalize tor->socks5, enforce rdns
        for h in hops:
            if h.get("type") == "tor":
                h["type"] = "socks5"
                h["remote_dns"] = True

        if not hops:
            return self._tcp_connect(final_host, final_port, self.timeout)

        s = None
        for i, hop in enumerate(hops):
            t = hop.get("type", "direct")
            if i == 0 and t != "direct":
                # physically connect to first hop
                s = self._tcp_connect(hop["host"], int(hop["port"]), self.timeout)

            # decide next target reached THROUGH this hop
            is_last_hop = (i == len(hops) - 1)
            next_host, next_port = (final_host, final_port) if is_last_hop else (hops[i+1]["host"], int(hops[i+1]["port"]))

            if t == "direct":
                if is_last_hop:
                    # no tunnel; just connect direct if we weren't already tunneled
                    if s is None:
                        s = self._tcp_connect(final_host, final_port, self.timeout)
                else:
                    # direct in the middle is effectively a no-op; ensure we have a TCP link to the next hop
                    if s is None:
                        s = self._tcp_connect(next_host, next_port, self.timeout)
                    else:
                        # already have a tunnel; we need to open TCP to next hop THROUGH that tunnel:
                        # use generic HTTP CONNECT to open raw TCP to next hop
                        s = self._http_connect(s, next_host, next_port, tls=False)
                continue

            if t == "socks5":
                # Optional Tor isolation: username/password provided by caller or hop
                s = self._socks5_connect(
                    s,
                    next_host, next_port,
                    remote_dns=bool(hop.get("remote_dns", True)),
                    username=hop.get("username"),
                    password=hop.get("password")
                )
            elif t == "http":
                s = self._http_connect(s, next_host, next_port, tls=bool(hop.get("tls", False)))
            else:
                raise ValueError(f"Unknown hop type: {t}")

        # After last hop we are connected to final target
        return s

# -------------------- Local SOCKS5 server --------------------

class LocalSocks5(threading.Thread):
    def __init__(self, listen_host, listen_port, base_chain_client, tor_isolate=False):
        super().__init__(daemon=True)
        self.lh, self.lp = listen_host, listen_port
        self.base_cc = base_chain_client
        self.tor_isolate = tor_isolate
        self.alive = True
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.lh, self.lp))
        self.server.listen(128)

    def run(self):
        while self.alive:
            try:
                c, addr = self.server.accept()
                threading.Thread(target=self.handle_client, args=(c,), daemon=True).start()
            except OSError:
                break

    def stop(self):
        self.alive = False
        try: self.server.close()
        except: pass

    def _per_connection_chain(self):
        chain = copy.deepcopy(self.base_cc.chain if hasattr(self.base_cc, "chain") else {"hops": self.base_cc.hops})
        if self.tor_isolate:
            token = secrets.token_hex(8)
            for h in chain.get("hops", []):
                # mark only TOR socks for isolation (identified by notes==tor OR 127.0.0.1:9050)
                if (h.get("type") in ("socks5","tor")) and (h.get("notes") == "tor" or (h.get("host")=="127.0.0.1" and int(h.get("port",0))==9050)):
                    h["username"] = token
                    h["password"] = "x"
        return chain

    def handle_client(self, cli):
        try:
            # Greeting
            hdr = cli.recv(2)
            if len(hdr)<2 or hdr[0]!=0x05:
                cli.close(); return
            nmethods = hdr[1]
            _ = cli.recv(nmethods)  # ignore offered methods
            cli.sendall(b"\x05\x00")  # no auth

            # Request
            req = cli.recv(4)
            if len(req)<4 or req[1]!=0x01:  # CONNECT only
                cli.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00"); cli.close(); return
            atyp = req[3]
            if atyp == 0x01:
                dst_addr = socket.inet_ntoa(cli.recv(4))
            elif atyp == 0x03:
                l = cli.recv(1)[0]; dst_addr = cli.recv(l).decode()
            elif atyp == 0x04:
                dst_addr = socket.inet_ntop(socket.AF_INET6, cli.recv(16))
            else:
                cli.close(); return
            dst_port = struct.unpack("!H", cli.recv(2))[0]

            # Dial chain (per-connection, to allow Tor isolation)
            per_chain = self._per_connection_chain()
            cc = ChainClient(per_chain)
            try:
                upstream = cc.dial(dst_addr, dst_port)
            except Exception:
                cli.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00"); cli.close(); return

            # Success
            cli.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            self.pump(cli, upstream)
        except Exception:
            try: cli.close()
            except: pass

    def pump(self, a, b):
        a.setblocking(False); b.setblocking(False)
        sockets = [a,b]
        try:
            while True:
                r,_,e = select.select(sockets, [], sockets, 300)
                if e: break
                if not r: break
                for s in r:
                    other = b if s is a else a
                    try:
                        data = s.recv(65535)
                        if not data:
                            return
                        other.sendall(data)
                    except OSError as ex:
                        if ex.errno in (errno.EAGAIN, errno.EWOULDBLOCK): continue
                        return
        finally:
            for s in (a,b):
                try: s.close()
                except: pass

# -------------------- Bench, scoring & watchdog --------------------

def try_connect_via(cc, target, attempts=3, timeout_ms=800):
    host, port = target
    best = 10_000_000
    ok = 0
    for _ in range(attempts):
        t0 = now_ms()
        try:
            s = cc.dial(host, port)
            s.close()
            dt = now_ms() - t0
            best = min(best, dt)
            ok += 1
        except:
            pass
        # crude timing guard
        if (now_ms() - t0) > timeout_ms:
            best = min(best, timeout_ms*2)
    return best, ok/attempts if attempts else 0.0

def score_proxy(lat_ms, success):
    penalty = (1.0 - success) * 2000.0
    return lat_ms + penalty
def _measure_proxy_metrics(p, bench_targets, attempts, timeout_ms):
    cc = ChainClient({"hops":[p]})
    lat_list, ok_list = [], []
    for t in bench_targets:
        lat, ok = try_connect_via(cc, t, attempts=attempts, timeout_ms=timeout_ms)
        lat_list.append(lat); ok_list.append(ok)
    lat_ms = min(lat_list) if lat_list else 9_999_999
    success = sum(ok_list)/len(ok_list) if ok_list else 0.0
    s = score_proxy(lat_ms, success)
    return {
        "latency_ms": int(lat_ms),
        "success": round(success, 3),
        "score": round(s, 1),
        "last_checked": int(time.time()),
    }

def diagnostics_select(inventory, bench_targets, attempts, timeout_ms, chain_size,
                       workers=8, bar_width=40):
    proxies = list(inventory.get("proxies", []))
    total = len(proxies)
    done = 0
    _render_progress(done, total, width=bar_width)

    # Threaded execution
    futures = {}
    try:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
            for p in proxies:
                fut = ex.submit(_measure_proxy_metrics, p, bench_targets, attempts, timeout_ms)
                futures[fut] = p

            for fut in as_completed(futures):
                p = futures[fut]
                try:
                    metrics = fut.result()
                except Exception:
                    metrics = {"latency_ms": 9_999_999, "success": 0.0, "score": 9_999_999.0,
                               "last_checked": int(time.time())}
                p["metrics"] = metrics
                done += 1
                _render_progress(done, total, width=bar_width)
    except KeyboardInterrupt:
        # Graceful cancel visual
        sys.stdout.write("\n[diagnostics] interrupted by user.\n")
        sys.stdout.flush()
        raise

    # Rank & select
    ranked = sorted(
        (p for p in proxies if p.get("metrics", {}).get("success", 0) > 0),
        key=lambda p: p["metrics"]["score"]
    )
    hops = ranked[:max(1, chain_size)]
    return {
        "hops": hops,
        "bench_targets": bench_targets,
        "bench_count": attempts,
        "bench_timeout_ms": timeout_ms
    }

class Watchdog(threading.Thread):
    def __init__(self, cc, probe=("1.1.1.1",443), interval=5, failures=3, killer=None):
        super().__init__(daemon=True)
        self.cc = cc
        self.probe = probe
        self.interval = interval
        self.failures = failures
        self.killer = killer
        self._stop = False
        self.baseline = None
        self.spike_started = None

    def run(self):
        misses = 0
        while not self._stop:
            time.sleep(self.interval)
            try:
                t0 = now_ms()
                s = self.cc.dial(*self.probe); s.close()
                rtt = now_ms() - t0
                misses = 0
                if self.baseline is None or rtt < self.baseline:
                    self.baseline = rtt
                    self.spike_started = None
                else:
                    # Spike policy: >4x baseline for >=30s
                    if self.baseline and rtt > 4*self.baseline:
                        self.spike_started = self.spike_started or now_ms()
                        if now_ms() - self.spike_started >= 30_000:
                            if self.killer: self.killer(); break
                    else:
                        self.spike_started = None
            except:
                misses += 1
                if misses >= self.failures and self.killer:
                    self.killer(); break

    def stop(self): self._stop = True

# -------------------- Tor control (optional) --------------------

class TorControl:
    def __init__(self, host, port, password=None):
        self.addr=(host,port); self.password=password; self.sock=None

    def _send(self, s): self.sock.sendall((s+"\r\n").encode())

    def _readlines(self, timeout=5):
        self.sock.settimeout(timeout)
        buf=b""; lines=[]
        while True:
            chunk=self.sock.recv(4096)
            if not chunk: break
            buf+=chunk
            while b"\r\n" in buf:
                line,buf=buf.split(b"\r\n",1); lines.append(line.decode())
                if line.startswith(b"250 ") or line == b"250 OK" or line.startswith(b"5"):
                    return lines

    def connect(self, timeout=5):
        self.sock=socket.create_connection(self.addr, timeout=timeout)
        _ = self._readlines()  # banner
        if self.password:
            self._send(f'AUTHENTICATE "{self.password}"')
        else:
            self._send("AUTHENTICATE")
        resp=self._readlines()
        if not resp or not any("250" in r for r in resp):
            raise OSError("Tor control auth failed")

    def get_bootstrap(self, timeout=30):
        t0=time.time()
        while time.time()-t0<timeout:
            self._send("GETINFO status/bootstrap-phase")
            lines=self._readlines()
            if lines:
                for ln in lines:
                    if "PROGRESS=" in ln:
                        try:
                            prog=int(ln.split("PROGRESS=")[1].split()[0].strip())
                            if prog>=100: return 100
                        except: pass
            time.sleep(1)
        return 0

    def newnym(self):
        self._send("SIGNAL NEWNYM"); _=self._readlines()

    def close(self):
        try:
            self._send("QUIT")
            self.sock.close()
        except: pass

def probe_socks(host, port, timeout=2.0):
    try:
        s=socket.create_connection((host,port), timeout=timeout)
        s.sendall(b"\x05\x01\x00")
        r=s.recv(2); s.close()
        return len(r)==2 and r[0]==5
    except: return False

def maybe_add_tor(inv, args):
    if args.tor_mode=="off": return inv
    th,tp=parse_hostport(args.tor_socks)
    if probe_socks(th,tp):
        tor_entry={"type":"tor","host":th,"port":tp,"remote_dns":True,"notes":"tor"}
        return merge_inventory(inv, [tor_entry])
    else:
        if args.tor_mode=="require":
            print("[tor] required but not available at", args.tor_socks); sys.exit(2)
        return inv

# -------------------- Shell / Exec / Env --------------------

def proxied_env(listen_host, listen_port, prompt_label="GHOSTNET"):
    env = os.environ.copy()
    proxy_url = f"socks5h://{listen_host}:{listen_port}"
    env["ALL_PROXY"] = proxy_url
    env["all_proxy"] = proxy_url
    env["http_proxy"] = proxy_url
    env["https_proxy"] = proxy_url
    env["no_proxy"] = ""

    # Cyan label, reset after, show user and cwd
    # \[ \] wrap non-printing sequences so readline calculates width correctly
    user = "root" if os.geteuid() == 0 else (env.get("USER") or "user")
    env["PS1"] = (
        r"\n"                 # <- add this newline
        r"\[\e[36m\]"           # cyan start
        + f"{prompt_label}({user})"
        r"\[\e[0m\]"            # reset
        r"[ \w ] > "            # space + working dir + >
    )
    env.pop("PROMPT_COMMAND", None)
    return env


import os, subprocess

def spawn_shell(env):
    # Merge to preserve PATH etc.
    merged_env = os.environ.copy()
    merged_env.update(env)
    # Inherit the current TTY/stdin/out/err by default (no PTY juggling)
    # This gives you proper job control, arrows, paste, etc.
    try:
        return subprocess.call(
            ["/bin/bash", "--noprofile", "--norc"],
            env=merged_env
        )
    except KeyboardInterrupt:
        return 130




def exec_once(env, cmd_argv):
    proc = subprocess.run(cmd_argv, env=env)
    return proc.returncode

# -------------------- Main --------------------

def main():
    ap = argparse.ArgumentParser(description="GhostNet — standalone chained proxy + proxied shell")
    ap.add_argument("--listen", default="127.0.0.1:9050", help="host:port to listen for local SOCKS5 (default 127.0.0.1:9050)")
    ap.add_argument("--prompt", default="GHOSTNET", help="Prompt label (default: GHOSTNET)")
    ap.add_argument("--bench", action="store_true", help="After start, run a quick chain latency bench (info only).")

    # Lifecycle
    ap.add_argument("--init", action="store_true", help="Parse proxies.txt into proxies.json (merge/new).")
    ap.add_argument("--diagnostics", action="store_true", help="Benchmark proxies and pick best order into active_chain.json.")
    ap.add_argument("--chain-size", type=int, default=1, help="How many hops to select during diagnostics (default 1).")
    ap.add_argument("--proxies-file", default="proxies.txt", help="Input TXT proxies list.")
    ap.add_argument("--inventory", default="proxies.json", help="Canonical JSON inventory.")
    ap.add_argument("--active", default="active_chain.json", help="Selected active chain JSON.")
    ap.add_argument("--bench-target", action="append", default=[], help="Extra bench targets host:port (can repeat).")
    ap.add_argument("--bench-count", type=int, default=3, help="Attempts per proxy/target during diagnostics.")
    ap.add_argument("--bench-timeout-ms", type=int, default=800, help="Timeout per attempt in ms.")
    ap.add_argument("--diag-workers", type=int, default=max(4, (os.cpu_count() or 4)),
                help="Number of worker threads for diagnostics (default: CPU count, min 4).")
    ap.add_argument("--diag-bar-width", type=int, default=40,
                help="Progress bar width during diagnostics (default: 40).")


    # Run modes
    ap.add_argument("--start", action="store_true", help="Start proxied shell using active_chain.json.")
    ap.add_argument("--chain", action="store_true", help="Alias of --start (kept for your muscle memory).")
    ap.add_argument("--exec", action="store_true", help="Single-shot exec mode; command after --")
    ap.add_argument("cmd", nargs=argparse.REMAINDER, help="command to run when using --exec (use -- to separate)")

    # Watchdog / kill-switch
    ap.add_argument("--probe", default="1.1.1.1:443", help="watchdog probe host:port (default 1.1.1.1:443)")
    ap.add_argument("--probe-interval", type=int, default=5, help="watchdog interval seconds")
    ap.add_argument("--probe-failures", type=int, default=3, help="consecutive failures before kill")

    # Tor integration
    ap.add_argument("--tor-mode", choices=["off","prefer","require"], default="prefer")
    ap.add_argument("--tor-socks", default="127.0.0.1:9050")
    ap.add_argument("--tor-control", default=None)
    ap.add_argument("--tor-password", default=None)
    ap.add_argument("--tor-isolate", action="store_true")
    ap.add_argument("--tor-newnym-on-start", action="store_true")
    ap.add_argument("--tor-newnym-interval", type=int, default=0)

    args = ap.parse_args()

    lh, lp = parse_hostport(args.listen, default_port=9050)

    # INIT
    if args.init:
        new_list = parse_proxies_txt(args.proxies_file)
        inv_old = load_json(args.inventory, {"proxies":[]})
        inv_new = merge_inventory(inv_old, new_list)
        # Tor auto-add (prefer/require)
        inv_new = maybe_add_tor(inv_new, args)
        save_json(args.inventory, inv_new)
        print(f"[init] parsed {len(new_list)} from {args.proxies_file} → {len(inv_new['proxies'])} in {args.inventory}")
        sys.exit(0)

    # DIAGNOSTICS
    if args.diagnostics:
        inv = load_json(args.inventory, {"proxies":[]})
        if not inv.get("proxies"):
            print("[diagnostics] inventory empty. Run --init first."); sys.exit(2)

        inv = maybe_add_tor(inv, args)  # ensure tor injected if available/required

		# Build bench target list
        targets = []
        if args.bench_target:
            for s in args.bench_target:
                h, p = parse_hostport(s)
                targets.append((h, p))
            
            if not targets:
                targets = [("1.1.1.1", 443), ("8.8.8.8", 443)]

		# Run threaded diagnostics with a live progress bar
        active = diagnostics_select(
            inv,
            targets,
            args.bench_count,
            args.bench_timeout_ms,
            args.chain_size,
            workers=args.diag_workers,
            bar_width=args.diag_bar_width
        )

        # Save results
        save_json(args.inventory, inv)   # updated metrics
        save_json(args.active, active)   # selected chain

        # Pretty-print top candidates, showing https:// when tls=True
        proxies_sorted = sorted(inv["proxies"], key=lambda p: p.get("metrics",{}).get("score", 9e9))
        print("[diagnostics] top candidates:")
        for i, p in enumerate(proxies_sorted[:10], 1):
            m = p.get("metrics", {})
            scheme = "https" if (p.get("type") == "http" and p.get("tls")) else p.get("type")
            print(f"  {i:02d}. {scheme}://{p['host']}:{p['port']}  "
                  f"score={m.get('score')}  latency={m.get('latency_ms')}ms  success={m.get('success')}")
        print(f"[diagnostics] selected {len(active['hops'])} hop(s) → {args.active}")
        sys.exit(0)


    # START / CHAIN / EXEC require an active chain
    if args.start or args.chain or args.exec:
        use_chain = load_json(args.active, None)
        if not use_chain:
            print(f"[start] No {args.active} found. Run --init and --diagnostics first.")
            sys.exit(2)
        chain = {"hops": []}
        chain.update(use_chain)
    else:
        # Nothing else requested; show help
        ap.print_help()
        sys.exit(0)

    # Optional Tor ControlPort
    tc=None
    if args.tor_mode!="off" and args.tor_control:
        ch,cp=parse_hostport(args.tor_control)
        try:
            tc=TorControl(ch,cp,args.tor_password); tc.connect()
            prog=tc.get_bootstrap(timeout=30)
            print(f"[tor] bootstrap {prog}%")
            if args.tor_newnym_on_start: tc.newnym()
            if args.tor_newnym_interval>0:
                def rotator():
                    while True:
                        time.sleep(args.tor_newnym_interval)
                        try: tc.newnym()
                        except: break
                threading.Thread(target=rotator, daemon=True).start()
        except Exception as e:
            print("[tor] control unavailable:", e)
            if args.tor_mode=="require": sys.exit(2)

    # Build client & start local SOCKS
    cc = ChainClient(chain)
    cc.chain = chain
    cc.tor_isolate = args.tor_isolate

    srv = LocalSocks5(lh, lp, cc, tor_isolate=args.tor_isolate)
    srv.start()
    print(f"[+] Local SOCKS5 listening on {lh}:{lp}")

    # Kill-switch watchdog
    probe_h, probe_p = parse_hostport(args.probe)
    def killer():
        print("\n[!] Chain unhealthy. Terminating session to avoid leaks.")
        try:
            os.killpg(0, 15)  # best-effort terminate our process group
        except Exception:
            os._exit(1)

    wd = Watchdog(cc, probe=(probe_h, probe_p), interval=args.probe_interval, failures=args.probe_failures, killer=killer)
    wd.start()

    # Optional quick bench of the chosen chain
    if args.bench and chain.get("bench_targets"):
        ms = min(try_connect_via(cc, t, attempts=2, timeout_ms=chain.get("bench_timeout_ms",800))[0] for t in chain["bench_targets"])
        print(f"[bench] chain RTT ≈ {ms} ms (min of {len(chain['bench_targets'])} targets)")

    env = proxied_env(lh, lp, prompt_label=args.prompt)
    rc = 0
    try:
        if args.exec:
            cmd = args.cmd
            if cmd and cmd[0] == "--": cmd = cmd[1:]
            if not cmd:
                print("Nothing to execute. Provide a command after --")
                rc = 2
            else:
                print(f"[exec] {' '.join(shlex.quote(x) for x in cmd)}")
                rc = exec_once(env, cmd)
        else:
            print("[shell] launching proxied bash. Type 'exit' to quit.")
            spawn_shell(env)
    except KeyboardInterrupt:
        rc = 130
    except SystemExit as e:
        rc = e.code if isinstance(e.code, int) else 1
    except Exception:
        traceback.print_exc()
        rc = 1
    finally:
        wd.stop()
        srv.stop()
        if tc: tc.close()
        sys.exit(rc)

if __name__ == "__main__":
    main()
