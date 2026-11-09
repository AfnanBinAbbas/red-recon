# red-recon

Phase 1 — passive + active footprint: DNS (A/MX/NS/TXT), WHOIS, HTTP fingerprint,
TLS cert hash. Writes `recon/recon.json` + raw logs.

```bash
./phases/01-recon.sh --target example.com [--ws DIR] [--egress tor]
```

Checkpoint: if `recon/recon.json` exists, skipped unless `--force`.
Authorized targets only.
