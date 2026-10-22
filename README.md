# mail-auth-check

Check **SPF, DMARC and DKIM** for any domain from the command line. One Python file, no dependencies (DNS-over-HTTPS via Cloudflare, fallback Google).

```bash
python3 mail_auth_check.py example.nl
python3 mail_auth_check.py example.nl --selectors default,google,selector1
python3 mail_auth_check.py example.nl --json
```

What it checks:
- **SPF:** record present, more than one record (permerror under RFC 7208), estimated DNS lookups (limit 10), `+all` / `?all`.
- **DMARC:** record present, policy (`none` / `quarantine` / `reject`), reporting address (`rua`).
- **DKIM:** tries common selectors (selectors cannot be listed via DNS).

Why it matters: in our study of 220 Dutch webshops, only 23.2% had DMARC set to quarantine or reject ([data](https://github.com/Joepify/webshop-onderzoek-2026)).

Prefer a browser? Use the free check at https://www.joepify.nl/email-check · Guide (Dutch): https://www.joepify.nl/kennisbank/dmarc-instellen

Made by [Joepify](https://www.joepify.nl), Rotterdam. MIT licence.
