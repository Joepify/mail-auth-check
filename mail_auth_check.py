#!/usr/bin/env python3
"""mail-auth-check: check SPF, DMARC and DKIM for a domain.

No dependencies: uses DNS-over-HTTPS (Cloudflare, fallback Google).
Usage:
    python3 mail_auth_check.py example.nl
    python3 mail_auth_check.py example.nl --selectors default,google,selector1,selector2
    python3 mail_auth_check.py example.nl --json

Made by Joepify (https://www.joepify.nl), MIT licence.
"""
import argparse, json, re, sys, urllib.parse, urllib.request

DOH = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"]
COMMON_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "s1", "s2", "x", "dkim", "mail", "smtp"]


def txt(name):
    """Return the TXT records for name (quotes joined)."""
    for base in DOH:
        url = f"{base}?name={urllib.parse.quote(name)}&type=TXT"
        req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
        try:
            data = json.load(urllib.request.urlopen(req, timeout=10))
        except Exception:
            continue
        return ["".join(re.findall(r'"([^"]*)"', a["data"])) or a["data"] for a in data.get("Answer", []) if a.get("type") == 16]
    raise RuntimeError("DNS-over-HTTPS lookup failed")


def check_spf(domain):
    recs = [r for r in txt(domain) if r.lower().startswith("v=spf1")]
    res = {"found": bool(recs), "records": recs, "issues": []}
    if len(recs) > 1:
        res["issues"].append("More than one SPF record: RFC 7208 treats this as a permerror.")
    if recs:
        r = recs[0]
        lookups = len(re.findall(r"\b(include:|a\b|a:|mx\b|mx:|ptr|exists:|redirect=)", r))
        res["dns_lookups_estimate"] = lookups
        if lookups > 10:
            res["issues"].append("More than 10 DNS lookups: RFC 7208 limit exceeded (permerror).")
        if r.rstrip().endswith("+all"):
            res["issues"].append("Ends with +all: anyone may send as this domain.")
        elif r.rstrip().endswith("?all"):
            res["issues"].append("Ends with ?all (neutral): offers little protection.")
    else:
        res["issues"].append("No SPF record.")
    return res


def check_dmarc(domain):
    recs = [r for r in txt("_dmarc." + domain) if r.lower().startswith("v=dmarc1")]
    res = {"found": bool(recs), "records": recs, "issues": []}
    if not recs:
        res["issues"].append("No DMARC record at _dmarc." + domain)
        return res
    tags = dict(t.strip().split("=", 1) for t in recs[0].split(";") if "=" in t)
    p = tags.get("p", "").lower()
    res["policy"] = p
    res["enforced"] = p in ("quarantine", "reject")
    if p == "none":
        res["issues"].append("Policy p=none: monitoring only, spoofed mail is not stopped.")
    if "rua" not in tags:
        res["issues"].append("No rua= address: you receive no aggregate reports.")
    return res


def check_dkim(domain, selectors):
    found = []
    for s in selectors:
        try:
            recs = [r for r in txt(f"{s}._domainkey.{domain}") if "p=" in r]
        except RuntimeError:
            continue
        if recs:
            found.append({"selector": s, "record": recs[0][:80] + ("..." if len(recs[0]) > 80 else "")})
    return {"found": bool(found), "selectors": found,
            "note": "DKIM selectors cannot be listed via DNS; only the selectors tried were checked."}


def main():
    ap = argparse.ArgumentParser(description="Check SPF, DMARC and DKIM for a domain.")
    ap.add_argument("domain")
    ap.add_argument("--selectors", default=",".join(COMMON_SELECTORS))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    d = a.domain.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0].removeprefix("www.")
    out = {"domain": d, "spf": check_spf(d), "dmarc": check_dmarc(d), "dkim": check_dkim(d, a.selectors.split(","))}
    if a.json:
        print(json.dumps(out, indent=2))
        return
    print(f"Domain: {d}")
    for k in ("spf", "dmarc", "dkim"):
        r = out[k]
        print(f"\n{k.upper()}: {'found' if r['found'] else 'NOT found'}")
        for rec in r.get("records", []):
            print("  record:", rec)
        if k == "dmarc" and r["found"]:
            print("  policy:", r.get("policy"), "(enforced)" if r.get("enforced") else "(not enforced)")
        for s in r.get("selectors", []):
            print(f"  selector {s['selector']}: {s['record']}")
        for i in r.get("issues", []):
            print("  ! " + i)
    print("\nFull check in your browser: https://www.joepify.nl/email-check")


if __name__ == "__main__":
    sys.exit(main())
