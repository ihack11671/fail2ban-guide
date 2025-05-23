# Comprehensive Guide to Hardening Nginx Against Slowloris Attacks Using Fail2Ban
**Created by: CCT Moses Bahati**  
**Last Updated: 2025-05-20**

## Table of Contents
1. [Introduction](#introduction)
2. [Basic Fail2Ban Setup](#basic-fail2ban-setup)
3. [Creating a Slowloris Filter](#creating-a-slowloris-filter)
4. [Nginx Configuration Hardening](#nginx-configuration-hardening)
5. [Creating Fail2Ban Jail Configuration](#creating-fail2ban-jail-configuration)
6. [Advanced Setup: Email Alerts Integration](#advanced-setup-email-alerts-integration)
7. [Testing Your Protection](#testing-your-protection)
8. [Common Fail2Ban Commands](#common-fail2ban-commands)
9. [Troubleshooting](#troubleshooting)
10. [Exporting Configuration as PDF](#exporting-configuration-as-pdf)

---

## Introduction
Slowloris is a type of Denial of Service (DoS) attack that allows a single machine to take down a server with minimal bandwidth by holding connections open for as long as possible. This guide provides a comprehensive approach to mitigating Slowloris attacks using Fail2Ban and Nginx configuration hardening.

---

## Basic Fail2Ban Setup

```bash
# Install Fail2Ban package
sudo apt update
sudo apt install fail2ban -y

# Verify installation
sudo systemctl status fail2ban
```

> **Note:** Fail2Ban works by monitoring log files for patterns that indicate malicious activity and applying temporary bans to offending IP addresses.

---

## Creating a Slowloris Filter

```bash
# Create a new filter configuration file
sudo nano /etc/fail2ban/filter.d/nginx-slowloris.conf
```

Add:
```ini
[Definition]
failregex = ^<HOST> .* "(GET|POST|HEAD).*HTTP.*" 408
            ^<HOST> .* "(GET|POST|HEAD).*HTTP.*" 400
            ^<HOST> \- \- \[\] "\w+ \S+ HTTP/\d\.\d" 499
ignoreregex =
```

---

## Nginx Configuration Hardening
THis is just to harden your server against different slow attacks, not necessarily a part of fail2ban. It is good to have these configurations

Edit the main config:

```bash
sudo nano /etc/nginx/nginx.conf
```

Add or update in `http { ... }`:

```nginx
http {
    client_body_timeout 7s;
    client_header_timeout 7s;
    keepalive_timeout 30s;
    send_timeout 10s;

    limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;
    limit_conn conn_limit_per_ip 10;

    limit_req_zone $binary_remote_addr zone=req_limit_per_ip:10m rate=10r/s;

    client_header_buffer_size 1k;
    large_client_header_buffers 4 8k;
    client_body_buffer_size 8k;
    client_max_body_size 1m;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
}
```

In your server block:

```nginx
server {
    limit_req zone=req_limit_per_ip burst=20 nodelay;
    # Other configs...
}
```

Test and reload, Just to ensure nginx works well after the configurations :

```bash
sudo nginx -t
sudo systemctl reload nginx
```

---

## Creating Fail2Ban Jail Configuration

```bash
sudo nano /etc/fail2ban/jail.local
```

Add:

```ini
[nginx-slowloris]
enabled = true
persistent = true
filter = nginx-slowloris
port = http,https
logpath = /var/log/nginx/access.log
logencoding = utf-8
maxretry = 5
findtime = 30
bantime = 172800
action = iptables-multiport[name=nginx, port="http,https", protocol=tcp]
```

Rename default conflicting file:

```bash
sudo mv /etc/fail2ban/jail.d/defaults-debian.conf /etc/fail2ban/jail.d/defaults-debian.conf.bak
```

Restart Fail2Ban:

```bash
sudo systemctl restart fail2ban
```

---

## Advanced Setup: Email Alerts Integration
To enable automated email alerts on your server, it's important to configure a trusted SMTP relay service. While this guide initially used Mailgun, I recommend SMTP2GO for its generous free tier and ease of integration. SMTP2GO allows your server (in this case, hosted on DigitalOcean) to relay emails securely using authenticated SMTP. This involves creating an account, obtaining your SMTP credentials (server, port, username, and password), and then configuring your domain’s DNS settings with SPF, DKIM, and CNAME records. These DNS records are essential to verify that your domain is authorized to send email on your behalf — helping to prevent spoofing and ensuring high deliverability. Once verified, your server can send email alerts (e.g., from Fail2Ban or other scripts) by using these credentials via Python or mail clients like msmtp or Postfix. The process is straightforward, and you can even use AI tools to help automate or validate your configuration.
1. **Set up Mailgun account**, get API key and domain.
2. **Create script** `/usr/local/bin/send-alerts.py`:

```python
#!/usr/bin/env python3
import requests
import subprocess

MAILGUN_API_KEY = "your-mailgun-api-key"
MAILGUN_DOMAIN = "your-mailgun-domain"
EMAIL_FROM = "Fail2Ban <security@yourdomain.com>"
EMAIL_TO = "your-email@example.com"

def get_ip_info(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            info = f"📊 IP Info for {ip}:\n"
            info += f"- Location: {data.get('city', 'Unknown')}, {data.get('region', 'Unknown')}, {data.get('country', 'Unknown')}\n"
            info += f"- Organization: {data.get('org', 'Unknown')}\n"
            info += f"- Hostname: {data.get('hostname', 'Unknown')}\n"
            return info
        else:
            return f"IP Info: Failed to fetch details for IP {ip} (HTTP {response.status_code})."
    except Exception as e:
        return f"IP Info: Error fetching IP details ({e})"

def get_log_lines(ip):
    try:
        cmd = ["grep", ip, "/var/log/fail2ban.log"]
        output = subprocess.check_output(cmd, text=True)
        return f"\n📜 Log Lines:\n{output.strip()}"
    except subprocess.CalledProcessError:
        return "\n📜 Log Lines: No log lines found for this IP."

def send_email(subject, message):
    try:
        url = f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages"
        auth = ("api", MAILGUN_API_KEY)
        data = {
            "from": EMAIL_FROM,
            "to": EMAIL_TO,
            "subject": subject,
            "text": message,
        }
        response = requests.post(url, auth=auth, data=data)
        if response.status_code == 200:
            print("Email sent successfully!")
        else:
            print(f"Failed to send email: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error sending email: {e}")

def send_alert(subject, message, ip=None):
    if ip:
        ip_info = get_ip_info(ip)
        logs = get_log_lines(ip)
        message += f"\n\n{ip_info}{logs}"
    send_email(subject, message)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 2:
        ip = sys.argv[2]
        send_alert("Fail2Ban Alert", sys.argv[1], ip)
    elif len(sys.argv) > 1:
        send_alert("Fail2Ban Alert", sys.argv[1])
    else:
        print("Usage: send-alerts.py <message> [ip]")
```
Using SMTP2GO SCRIPT :

```
#!/usr/bin/env python3
import requests
import subprocess

# SMTP2GO Configuration
SMTP2GO_API_KEY = "your-smtp2go-api-key"
EMAIL_TO = "your@email.com"
EMAIL_FROM = "alerts@yourdomain.com"

def get_ip_info(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        if response.status_code == 200:
            data = response.json()
            if data["status"] == "success":
                return (
                    f"IP Info:\n"
                    f"- IP: {data['query']}\n"
                    f"- Country: {data['country']}\n"
                    f"- Region: {data['regionName']}\n"
                    f"- City: {data['city']}\n"
                    f"- ISP: {data['isp']}"
                )
        return f"IP Info: Unable to fetch details for IP {ip}."
    except Exception as e:
        return f"IP Info: Error fetching IP details ({e})"

def get_log_lines(ip):
    try:
        cmd = ["grep", ip, "/var/log/fail2ban.log"]
        output = subprocess.check_output(cmd, text=True)
        return f"\n📜 Log Lines:\n{output.strip()}"
    except subprocess.CalledProcessError:
        return "\n📜 Log Lines: No log lines found for this IP."

def send_email(subject, message):
    try:
        response = requests.post(
            "https://api.smtp2go.com/v3/email/send",
            json={
                "api_key": SMTP2GO_API_KEY,
                "to": [EMAIL_TO],
                "sender": EMAIL_FROM,
                "subject": subject,
                "text_body": message,
                "html_body": f"<pre>{message}</pre>"
            }
        )
        if response.status_code == 200:
            print("✅ Email sent successfully.")
        else:
            print(f"❌ Failed to send email: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"⚠️ Error sending email: {e}")

def send_alert(subject, message, ip=None):
    if ip:
        ip_info = get_ip_info(ip)
        logs = get_log_lines(ip)
        message += f"\n\n{ip_info}{logs}"
    send_email(subject, message)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 2:
        ip = sys.argv[2]
        send_alert("Fail2Ban Alert", sys.argv[1], ip)
    elif len(sys.argv) > 1:
        send_alert("Fail2Ban Alert", sys.argv[1])
    else:
        print("Usage: send-alerts.py <message> [ip]")

```
Make it executable:

```bash
sudo chmod +x /usr/local/bin/send-alerts.py
```

**Create custom action:** `/etc/fail2ban/action.d/custom-mwl.conf`:

```ini
[Definition]
actionstart = iptables -N f2b-<name>
              iptables -I INPUT -p tcp -j f2b-<name>
actionstop = iptables -D INPUT -p tcp -j f2b-<name>
             iptables -F f2b-<name>
             iptables -X f2b-<name>
actioncheck = iptables -n -L INPUT | grep -q f2b-<name>
actionban = iptables -I f2b-<name> 1 -s <ip> -j REJECT
            /usr/local/bin/send-alerts.py "🚨 IP Banned in jail <name>: <ip>" <ip>
actionunban = iptables -D f2b-<name> -s <ip> -j REJECT
              /usr/local/bin/send-alerts.py "✅ IP Unbanned in jail <name>: <ip>" <ip>
```

In `jail.local` update to use:

```
action = custom-mwl
```
full updated file :
```
[nginx-slowloris]
persistent = true
enabled = true
filter = nginx-slowloris
port = http,https
logpath = /var/log/nginx/access.log
logencoding = utf-8
maxretry = 5
findtime = 30
bantime = 172800
action = custom-mwl

```

Restart Fail2Ban again:

```bash
sudo systemctl restart fail2ban
```

---

## Testing Your Protection

### Using SlowHTTPTest

Install and run:

```bash
sudo apt install slowhttptest -y
slowhttptest -c 1000 -H -g -o slowhttp -i 10 -r 200 -t GET -u http://your-domain-or-ip -x 24 -p 3
```

- `-c 1000`: 1000 connections
- `-H`: Slowloris mode
- `-g`: CSV output
- `-o slowhttp`: output filename prefix
- `-i 10`: interval 10s
- `-r 200`: 200 connections/sec
- `-t GET`: GET requests
- `-u`: Target URL

Monitor Fail2Ban logs in another terminal:

```bash
sudo tail -f /var/log/fail2ban.log
```

### Manual IP Ban Test

Ban an IP:

```bash
sudo fail2ban-client set nginx-slowloris banip 192.168.1.100
```

Unban:

```bash
sudo fail2ban-client set nginx-slowloris unbanip 192.168.1.100
```

Check status:

```bash
sudo fail2ban-client status nginx-slowloris
```

---

## Common Fail2Ban Commands

```bash
sudo fail2ban-client status
sudo fail2ban-client status nginx-slowloris
sudo systemctl restart fail2ban
sudo systemctl status fail2ban
sudo fail2ban-client status nginx-slowloris
sudo tail -n 1000 /var/log/fail2ban.log | grep "Ban"
sudo tail -f /var/log/nginx/error.log
```

---

## Troubleshooting

- **Fail2Ban logs:**  
  `sudo tail -f /var/log/fail2ban.log`
- **Test your filter:**  
  `sudo fail2ban-regex /var/log/nginx/access.log /etc/fail2ban/filter.d/nginx-slowloris.conf`
- **Check iptables:**  
  `sudo iptables -L -n`
- **Make sure logs are readable:**  
  `sudo chmod 644 /var/log/nginx/access.log`
- **Nginx log format:**  
  `sudo tail -n 20 /var/log/nginx/access.log`

---
**Note**: Always test configuration in a development environment.  
**Security Warning**: Replace example credentials with real values.  
---

*This guide was created by CCT Moses Bahati. For updates and additional security configurations, contact the author.*
