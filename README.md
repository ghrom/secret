# Secret

Zero-knowledge, self-destructing secret sharing. Three files. No dependencies. No build step. No accounts. No telemetry.

**Live:** [propercode.co.uk/onetimesecret](https://www.propercode.co.uk/onetimesecret/)

## How it works

```
CREATE:
  Browser generates AES-256-GCM key
  → encrypts your secret locally
  → sends only ciphertext to server
  → server stores it, returns an ID
  → browser builds URL: /secret/#ID-KEY

SHARE:
  You send the link to someone.
  The #fragment (containing the key) is never sent to the server.

VIEW:
  Recipient opens the link
  → browser extracts key from #fragment
  → fetches ciphertext from server (server deletes it immediately)
  → decrypts locally in the browser
  → secret is displayed, then gone forever
```

The server never sees your plaintext or your key. It stores ciphertext it cannot decrypt. After one view, even the ciphertext is gone.

## Deploy

Copy three files to any PHP-enabled web server:

```
secret/
  index.html     Single-page app (HTML + CSS + JS, all inline)
  controller.php  Controller — REST backend (~140 lines, PHP)
  model.sqlite     Model — auto-created by controller on first use
  .htaccess      Denies direct access to the SQLite database
```

Requirements:
- PHP with the `sqlite3` extension
- Directory writable by the web server (for SQLite auto-creation)
- That's it

```bash
# Example
cp index.html controller.php .htaccess /var/www/yoursite/secret/
chown www-data:www-data /var/www/yoursite/secret/
```

No npm. No composer. No Docker. No config files. No database setup. No environment variables.

## Features

- **AES-256-GCM** encryption (Web Crypto API)
- **Zero-knowledge** — server never sees plaintext or keys
- **Self-destructing** — deleted after first view
- **24-hour expiry** — auto-cleanup of unread secrets
- **Rate limiting** — 20 creates per IP per hour
- **100KB max** — keeps it focused on secrets, not file sharing
- **Dark theme** with lock animations
- **Mobile-responsive**
- **No external dependencies** — no CDNs, no frameworks, no tracking

## Security model

| What | Where |
|------|-------|
| Plaintext | Only in sender's and recipient's browser memory |
| Encryption key | Only in the URL fragment (`#`), never sent to server |
| Ciphertext | Server (SQLite), deleted after first read or 24h |
| IV | Server (SQLite), alongside ciphertext |

The URL fragment is never included in HTTP requests, server logs, or referrer headers. The server is a dumb ciphertext locker that self-empties.

## Why

Because sharing passwords and keys over email, Slack, or Teams leaves them sitting in plaintext forever. This gives you a link that works once and then ceases to exist.

And because the existing solutions are either SaaS platforms that want your money and data, or 50-file projects with Docker and Redis and npm and a build pipeline. This is three files.

## License

Propercode had this idea. Feel free to have this idea as well.

[ultimatelaw.org/79](https://ultimatelaw.org/79/)
