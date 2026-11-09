#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/checkpoint.sh"

usage() { echo "usage: 01-recon.sh --target <host|url|ip> [--ws DIR] [--egress direct|tor] [--force]"; }

parse_common_args "$@"
init_workspace

if skip_if_checkpoint "recon/recon.json" "recon"; then mark_phase_done recon; exit 0; fi

require_tools curl python3

HOST="$(target_host)"
URL="$(target_url)"
RAW="$WS/recon/raw"
mkdir -p "$RAW"

log "recon passive: $HOST"

python3 - "$HOST" "$URL" "$RAW" "$WS/recon/recon.json" <<'PY'
import json, subprocess, sys, socket, ssl, re, urllib.request, urllib.error
from datetime import datetime, timezone

host, url, raw, outp = sys.argv[1:5]
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
res = {"engagement_target": host, "started": datetime.now(timezone.utc).isoformat(), "dns": {}, "http": {}, "tls": {}, "whois": {}}

def sh(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return p.stdout.strip()
    except Exception as e:
        return f"ERR:{e}"

def grab(name, cmd, timeout=30):
    out = sh(cmd, timeout)
    open(f"{raw}/{name}", "w").write(out)
    return out

try:
    res["dns"]["a"] = socket.getaddrinfo(host, None)
    res["dns"]["a"] = sorted({x[4][0] for x in res["dns"]["a"]})
except Exception as e:
    res["dns"]["a"] = f"ERR:{e}"

res["dns"]["mx"] = grab("dns_mx", f"dig +short MX {host} 2>/dev/null || host -t MX {host} 2>/dev/null")
res["dns"]["ns"] = grab("dns_ns", f"dig +short NS {host} 2>/dev/null || host -t NS {host} 2>/dev/null")
res["dns"]["txt"] = grab("dns_txt", f"dig +short TXT {host} 2>/dev/null")
res["whois"]["record"] = grab("whois", f"whois {host} 2>/dev/null | head -80")

req = urllib.request.Request(url, headers={"User-Agent": UA})
try:
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    r = urllib.request.urlopen(req, timeout=25, context=ctx)
    body = r.read(8000)
    open(f"{raw}/http_head.txt","w").write(str(dict(r.headers)))
    open(f"{raw}/http_body.html","wb").write(body)
    res["http"] = {"status": r.status, "headers": dict(r.headers), "server": r.headers.get("Server"),
                   "powered_by": r.headers.get("X-Powered-By"), "title": (re.search(rb"<title[^>]*>([^<]+)", body, re.I) or [None,b""])[1].decode(errors="ignore") if re.search(rb"<title", body, re.I) else ""}
except Exception as e:
    res["http"] = {"error": str(e)}

try:
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    with socket.create_connection((host, 443), timeout=10) as s:
        with ctx.wrap_socket(s, server_hostname=host) as ss:
            cert = ss.getpeercert(True)
            import hashlib
            res["tls"]["sha256"] = hashlib.sha256(cert).hexdigest()
            res["tls"]["cipher"] = ss.cipher()
except Exception as e:
    res["tls"] = {"error": str(e)}

res["finished"] = datetime.now(timezone.utc).isoformat()
json.dump(res, open(outp,"w"), indent=2, default=str)
print("recon.json written")
PY

mark_phase_done recon
