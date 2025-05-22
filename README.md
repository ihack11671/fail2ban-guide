# Nginx & Fail2Ban Slowloris Protection Guide

**Author:** CCT Moses Bahati  
**Last Updated:** 2025-05-20

---

## 📄 Description

**Harden your Nginx server against Slowloris attacks using Fail2Ban!**  
This guide walks you step-by-step through installing, configuring, and testing robust protection for your web server.  
You’ll also learn how to receive real-time email alerts and manually manage bans for maximum security.

---

## 📚 Table of Contents

- [Introduction](#introduction)
- [Basic Fail2Ban Setup](#basic-fail2ban-setup)
- [Creating a Slowloris Filter](#creating-a-slowloris-filter)
- [Nginx Configuration Hardening](#nginx-configuration-hardening)
- [Creating Fail2Ban Jail Configuration](#creating-fail2ban-jail-configuration)
- [Advanced Setup: Email Alerts Integration](#advanced-setup-email-alerts-integration)
- [Testing Your Protection](#testing-your-protection)
- [Manual IP Banning](#manual-ip-banning)
- [Common Fail2Ban Commands](#common-fail2ban-commands)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## 🛡️ Introduction

Slowloris is a Denial of Service (DoS) attack that can exhaust server resources by holding multiple connections open.  
This guide helps you defend Nginx servers using Fail2Ban and modern configuration techniques.

---

## 🚀 Quick Start

```bash
# Install Fail2Ban
sudo apt update
sudo apt install fail2ban

# Install SlowHTTPTest for testing
sudo apt install slowhttptest

# Test Nginx using SlowHTTPTest (replace URL)
slowhttptest -c 1000 -H -g -o slowhttp -i 10 -r 200 -t GET -u http://your-domain-or-ip -x 24 -p 3
```

---

## 📝 Highlights

- **Fail2Ban filter** for Nginx Slowloris detection
- **Nginx hardening** with timeouts, rate limiting, and connection limits
- **Custom jails** to automatically ban attackers
- **Email alerts**: get notified on ban/unban events (Mailgun integration)
- **Testing instructions** using SlowHTTPTest
- **Manual ban/unban commands** for admins
- **Troubleshooting**

---

## 🤝 Contributing

Contributions, suggestions, and improvements are welcome!  
Please open an issue or submit a pull request.

---

## 📄 License

This project and its documentation are released under the MIT License.

---

*Guide maintained by CCT Moses Bahati – Africa CyberSecurity Consortium(ACC) && wilLtech academy Cybersecurity && CybExplore.*
