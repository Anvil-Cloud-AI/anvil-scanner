# OpenClaw Security Guide

OpenClaw is a powerful AI orchestration platform. By default it binds to several ports that should **never** be directly exposed to the public internet. This guide explains why and how to lock things down properly.

---

## Why OpenClaw's Ports Should Not Be Public

OpenClaw uses these ports by default:

| Port  | Service |
|-------|---------|
| 18789 | OpenClaw Gateway (main API) |
| 18791 | OpenClaw Gateway (WebSocket) |
| 9090  | Metrics / internal API |
| 19001 | Agent communication |

**The problem:** If these ports are directly reachable from the internet, anyone can attempt to:
- Enumerate your installed agents and capabilities
- Probe authentication endpoints with brute-force attacks
- Exploit any vulnerabilities in the gateway before patches are applied
- Consume your API quota by sending unauthorized requests

**The solution:** Sit a reverse proxy (like nginx) in front of OpenClaw, and use a firewall to block direct access to these ports from outside.

---

## Step 1: Block the Ports with ufw

`ufw` (Uncomplicated Firewall) is the simplest way to manage Linux firewall rules.

**Install ufw if not present:**

```bash
sudo apt-get install ufw   # Debian/Ubuntu
sudo dnf install ufw       # Fedora
```

**Block OpenClaw ports from all external access:**

```bash
# Deny incoming connections to OpenClaw ports from anywhere
sudo ufw deny 18789/tcp
sudo ufw deny 18791/tcp
sudo ufw deny 9090/tcp
sudo ufw deny 19001/tcp
```

**Allow only from your own IP or VPN network:**

```bash
# Replace 203.0.113.5 with your actual IP or CIDR range
sudo ufw allow from 203.0.113.5 to any port 18789
sudo ufw allow from 203.0.113.5 to any port 18791

# For a VPN subnet (e.g., 10.8.0.0/24):
sudo ufw allow from 10.8.0.0/24 to any port 18789
sudo ufw allow from 10.8.0.0/24 to any port 18791
```

**Enable ufw:**

```bash
sudo ufw enable
sudo ufw status verbose
```

---

## Step 2: Set Up a Reverse Proxy with nginx

A reverse proxy sits between the internet and OpenClaw. Browsers and clients connect to nginx on standard HTTPS (port 443), and nginx forwards requests to OpenClaw internally. This gives you:

- TLS/HTTPS termination (OpenClaw itself doesn't need to manage certificates)
- Rate limiting and request filtering at the proxy layer
- A standard port (443) instead of obscure port numbers
- Ability to add HTTP authentication as an extra layer

**Install nginx:**

```bash
sudo apt-get install nginx certbot python3-certbot-nginx  # Debian/Ubuntu
```

**Example nginx config** — save as `/etc/nginx/sites-available/openclaw`:

```nginx
# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name openclaw.yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name openclaw.yourdomain.com;

    # TLS certificate (get with: certbot --nginx -d openclaw.yourdomain.com)
    ssl_certificate     /etc/letsencrypt/live/openclaw.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/openclaw.yourdomain.com/privkey.pem;

    # Recommended TLS settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;

    # Rate limiting (define zone in http{} block: limit_req_zone $binary_remote_addr zone=openclaw:10m rate=10r/s;)
    limit_req zone=openclaw burst=20 nodelay;

    # Proxy to OpenClaw Gateway
    location / {
        proxy_pass http://127.0.0.1:18789;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
    }
}
```

**Enable the site and get a certificate:**

```bash
sudo ln -s /etc/nginx/sites-available/openclaw /etc/nginx/sites-enabled/
sudo nginx -t  # Test config
sudo systemctl reload nginx
sudo certbot --nginx -d openclaw.yourdomain.com
```

---

## Step 3: Secure Your API Keys

API keys and credentials should never be stored in plaintext config files. If your server is compromised, plaintext API keys are immediately stolen.

**Check your current config for exposed secrets:**

```bash
grep -i "api_key\|secret\|token\|password" ~/.openclaw/openclaw.json 2>/dev/null
```

**Best practices:**

- Set API keys as environment variables, not in config files
- Use your shell profile (`~/.bashrc`) or a systemd environment file
- Never commit secrets to git — add `*.env` and `secrets*` to `.gitignore`

---

## API Key Security Best Practices

### Rotate keys regularly

API keys should be rotated periodically and immediately if you suspect compromise:

1. Generate a new key from the provider's dashboard
2. Update it in OpenClaw's secrets store: `openclaw secrets set PROVIDER_API_KEY new-key`
3. Revoke the old key from the provider dashboard
4. Verify things still work before deleting the old key

### Use least-privilege keys

Most AI providers let you create API keys with specific permissions or rate limits:
- Create a dedicated key for OpenClaw (not your personal dev key)
- If the provider supports it, restrict the key to only the models/APIs OpenClaw needs
- Set spending limits if the provider supports it

### Never commit keys to git

```bash
# Add to .gitignore
echo "*.env" >> .gitignore
echo "config.env" >> .gitignore
echo ".openclaw/secrets*" >> .gitignore
```

Scan your repo for accidentally committed secrets:

```bash
git log -p | grep -E "(sk-|api_key|secret|token)" | head -20
```

### Monitor for unauthorized use

Set up alerts in your API provider dashboard for:
- Unusual spending spikes
- Requests from unexpected IP addresses
- Off-hours usage

---

## Step 4: Additional Hardening Checklist

- [ ] OpenClaw gateway only listens on `127.0.0.1`, not `0.0.0.0`
- [ ] nginx is configured with TLS 1.2+ only
- [ ] fail2ban is watching OpenClaw's access log (see [fail2ban-setup.md](fail2ban-setup.md))
- [ ] ufw blocks direct access to ports 18789/18791/9090/19001
- [ ] All API keys are in the encrypted secrets store, not plaintext files
- [ ] OpenClaw runs as a non-root user with minimal system permissions
- [ ] Logs are being monitored (e.g., via the Anvil-Secure report)

---

## Sources

- [nginx documentation](https://nginx.org/en/docs/) — reverse proxy and SSL configuration
- [ufw manual](https://manpages.ubuntu.com/manpages/focal/en/man8/ufw.8.html) — firewall rule management
- [Let's Encrypt](https://letsencrypt.org/) — free TLS certificates
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/) — API security best practices
