<p align="center">
  <img src="ghostnet.png" alt="GhostNet Banner" width="100%">
</p>

# 🕸️ GhostNet 

> **Standalone Proxy Chaining & OPSEC Shell**
> A no-dependency Python toolkit for proxy chaining, diagnostics, Tor integration, and proxied shells — built for Kali Linux.
> By Kranidiotis Nikolaos
---

## ⚡ Overview

GhostNet is a **standalone network proxy orchestrator** designed for red teams, researchers, and OPSEC-conscious operators.

* Runs entirely from **one Python file** (`ghostnet.py`)
* **No external dependencies** — only Python stdlib
* Provides a **local SOCKS5 proxy** bound to `127.0.0.1:9050`
* Launches a **branded shell** (`GHOSTNET(user)[ ~/dir ] >`) with proxy environment
* Supports **multi-hop chains**, `exec` one-shot commands, and **kill-switch safety**
* Optional **Tor integration** with stream isolation and NEWNYM control

GhostNet aims to be the **proxychains of the future**, but fully self-contained.

---

## 📦 Requirements

```text
python>=3.9
```

Everything else (argparse, socket, ssl, threading, json, subprocess, pty, select, etc.) is built into Python.

### OS / Environment

* Linux only (tested on **Kali**).
* `/bin/bash` available (for proxied shell mode).
* Optional: [Tor](https://www.torproject.org/) running locally for `--tor-mode` features.
* Optional: `jq` (or any JSON viewer) if you want to pretty-print `active_chain.json`.

---

## 🚀 Features

* **Local SOCKS5 proxy** (default: `127.0.0.1:9050`)
* **Proxy chain selection**: `proxies.txt` → `proxies.json` → `active_chain.json`
* **Diagnostics** with multithreading + live progress bar
* **Branded GhostNet shell** with cyan PS1 prompt
* **Exec mode**: run a single proxied command
* **Kill-switch watchdog**: terminates session if chain fails or leaks
* **Tor support**: SOCKS integration, ControlPort (NEWNYM), per-connection stream isolation
* **Flexible proxy input**:

  * `scheme://user:pass@host:port`
  * `host port type`
  * bare `host:port`
  * `tor` alias

---

## 🗂️ File Workflow

* **`proxies.txt`** → raw source list (one per line).
* **`proxies.json`** → inventory (normalized JSON with proxy metadata + metrics).
* **`active_chain.json`** → final active hop list (used by `--start` / `--exec`).

---

## 🔧 Usage

### 1. Initialize inventory

```bash
python3 ghostnet.py --init
```

Parses `proxies.txt` into `proxies.json`.
Auto-detects Tor SOCKS if available.

---

### 2. Run diagnostics

```bash
python3 ghostnet.py --diagnostics \
  --bench-target www.cloudflare.com:443 \
  --bench-target www.google.com:443 \
  --bench-count 1 --bench-timeout-ms 700 \
  --diag-workers 64 --diag-fast --dial-timeout 2.0 \
  --chain-size 2
```

* Multithreaded check of all proxies
* Ranks by latency + reliability
* Writes best hops to `active_chain.json`

---

### 3. Start proxied shell

```bash
python3 ghostnet.py --start
```

Launches SOCKS5 on `127.0.0.1:9050` and drops into a shell:

```
GHOSTNET(user)[ ~/Desktop ] >
```

All traffic (curl, wget, apt, etc.) goes through the chain.
Type `exit` to close the session.

---

### 4. Run single command

```bash
python3 ghostnet.py --exec -- curl -s https://ifconfig.me
```

Executes the command under the proxy and exits with its return code.

---

## 🛡️ Kill-Switch

GhostNet continuously probes chain health. If proxies fail or latency spikes:

* `[!] Chain unhealthy. Terminating session to avoid leaks.`
* The proxied shell is terminated instantly.

This ensures no traffic leaks to the clearnet.

---

## 🧅 Tor Integration

* `--tor-mode {off,prefer,require}` — auto-detect or enforce Tor usage
* `--tor-isolate` — enable per-connection stream isolation
* `--tor-control` — connect to Tor ControlPort (for NEWNYM, bootstrap %)
* `--tor-newnym-on-start` — request a new circuit on session start
* `--tor-newnym-interval` — periodic NEWNYM while running

---

## 📖 CLI Reference

### General

* `--listen host:port` → Local SOCKS5 bind (**127.0.0.1:9050** by default)
* `--prompt LABEL` → Shell prompt label (**GHOSTNET**)
* `--bench` → Print quick RTT after chain setup

### Lifecycle

* `--init` → Build inventory from `proxies.txt`
* `--diagnostics` → Benchmark proxies and select best hops
* `--chain-size N` → Number of hops (default 1)
* `--bench-target host:port` → Target(s) for diagnostics
* `--bench-count N` → Attempts per proxy (default 3)
* `--bench-timeout-ms MS` → Timeout per attempt (default 800)
* `--diag-workers N` → Threads for diagnostics
* `--diag-bar-width N` → Progress bar width

### Run Modes

* `--start` / `--chain` → Start SOCKS5 + GhostNet shell
* `--exec -- <cmd …>` → Run a proxied command and exit

### Kill-Switch / Watchdog

* `--probe host:port` → Health check target (default: 1.1.1.1:443)
* `--probe-interval SEC` → Probe interval (default: 5s)
* `--probe-failures N` → Fail count before kill (default: 3)

### Tor

* `--tor-mode {off,prefer,require}` → Tor usage mode
* `--tor-socks host:port` → Tor SOCKS endpoint (default: 127.0.0.1:9050)
* `--tor-control host:port` → Tor ControlPort
* `--tor-password` → ControlPort password
* `--tor-isolate` → Stream isolation
* `--tor-newnym-on-start` → New circuit at startup
* `--tor-newnym-interval SEC` → Periodic NEWNYM

---

## ✅ Example Session

```bash
python3 ghostnet.py --init
python3 ghostnet.py --diagnostics --bench-target www.cloudflare.com:443 --chain-size 2
python3 ghostnet.py --start

GHOSTNET(user)[ ~/ ] > curl -s https://ifconfig.me
167.71.34.74
```

---

## ⚠️ Disclaimer

This tool is for **educational and research purposes only**.
You are solely responsible for how you use GhostNet.
