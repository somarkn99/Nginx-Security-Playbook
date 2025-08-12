
# 🛡 Nginx Security Playbook

This playbook contains best practices, configurations, and advanced techniques for hardening and securing Nginx web servers.

---

## 1. Use HTTPS (TLS/SSL)
**Purpose:** Encrypt traffic to prevent eavesdropping and Man-in-the-Middle (MITM) attacks.

**Implementation:**
```nginx
server {
    listen 443 ssl http2;
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'HIGH:!aNULL:!MD5';
    ssl_prefer_server_ciphers on;
}
```

---

## 2. HTTP Security Headers
**Purpose:** Protect against common attacks like XSS, clickjacking, and MIME sniffing.

**Implementation:**
```nginx
add_header X-Content-Type-Options "nosniff";
add_header X-Frame-Options "SAMEORIGIN";
add_header X-XSS-Protection "1; mode=block";
add_header Referrer-Policy "no-referrer-when-downgrade";
add_header Content-Security-Policy "default-src 'self'";
```

---

## 3. Request Size Limits
**Purpose:** Prevent buffer overflows and resource abuse from large uploads.

**Implementation:**
```nginx
client_max_body_size 10M;
client_body_timeout 12;
```

---

## 4. Rate Limiting
**Purpose:** Mitigate brute-force and low-level DoS attacks.

**Implementation:**
```nginx
limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/m;

location /login {
    limit_req zone=login_limit burst=10 nodelay;
}
```

---

## 5. Hide Nginx Version
**Purpose:** Avoid exposing the Nginx version to attackers.

**Implementation:**
```nginx
server_tokens off;
```

---

## 6. Restrict Access to Sensitive Files
**Purpose:** Block access to hidden and configuration files.

**Implementation:**
```nginx
location ~ /\.(?!well-known) {
    deny all;
}
```

---

## 7. Restrict Access to Admin Routes
**Purpose:** Limit sensitive areas to specific IPs or require authentication.

**Implementation:**
```nginx
location /horizon {
    auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/.htpasswd;
    allow 192.168.1.0/24;
    deny all;
}
```

---

## 8. Integrate with Fail2ban
**Purpose:** Automatically ban IPs based on Nginx log events.

**Implementation (jail.local):**
```
[nginx-req-limit]
enabled = true
filter = nginx-req-limit
logpath = /var/log/nginx/error.log
maxretry = 5
bantime = 3600
```

---

## 9. Run Nginx with Least Privileges
**Purpose:** Minimize damage if compromised.

**Implementation:**
- Run as a non-root user where possible.
- Use Docker networks to isolate services.

---

## 10. Real IP with Cloudflare
**Purpose:** Ensure Nginx logs show the real client IP.

**Implementation:**
```nginx
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
real_ip_header CF-Connecting-IP;
```

---

## 11. Bot/User-Agent Based Blocking
**Purpose:** Block automated scanners and scraping tools.

**Implementation:**
```nginx
map $http_user_agent $block_bots {
    default         0;
    ~*curl|wget|python  1;
}

server {
    if ($block_bots) {
        return 403;
    }
}
```

---

## 12. Basic SQL Injection Pattern Blocking
**Purpose:** Block basic malicious query patterns.

**Implementation:**
```nginx
if ($query_string ~* "union.*select.*\(") {
    return 403;
}
```

---

## 13. HSTS (HTTP Strict Transport Security)
**Purpose:** Force HTTPS usage for clients.

**Implementation:**
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

---

## 14. Caching Static Files
**Purpose:** Improve performance and reduce attack surface.

**Implementation:**
```nginx
location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
    expires 30d;
    add_header Cache-Control "public, no-transform";
}
```

---

## 15. Virtual Host Isolation
**Purpose:** Prevent lateral movement between hosted sites.

**Implementation:**
- Separate `server` blocks per site.
- Different file permissions and users.

---

## 16. Logging Tuning
**Purpose:** Focus logging on suspicious activity.

**Implementation:**
```nginx
map $status $loggable {
    ~^[23]  0;
    default 1;
}
access_log /var/log/nginx/access.log combined if=$loggable;
```

---

## 17. GeoIP Blocking
**Purpose:** Block traffic from specific countries.

**Implementation:**
```nginx
geoip_country /etc/nginx/geoip/GeoIP.dat;

if ($geoip_country_code = "CN") {
    return 403;
}
```

---

## 18. Hotlink Protection
**Purpose:** Prevent unauthorized embedding of site resources.

**Implementation:**
```nginx
location ~* \.(jpg|jpeg|png|gif|ico)$ {
    valid_referers none blocked yoursite.com *.yoursite.com;
    if ($invalid_referer) {
        return 403;
    }
}
```

---

## 19. Security Monitoring Integration
**Purpose:** Send logs to centralized SIEM for analysis.

**Tools:** Loki, Promtail, Grafana.

**Implementation:**
- Configure Nginx to log in JSON format.
- Use Promtail to ship logs to Loki.
- Visualize in Grafana for real-time detection.

---

## 20. Automation and Maintenance
- Keep Nginx updated to the latest stable version.
- Regularly review logs for anomalies.
- Test configurations with `nginx -t` before applying.

---

---

## 21. WAF Integration
**Purpose:** Add a Web Application Firewall layer directly into Nginx using ModSecurity or NAXSI.
```nginx
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
```
> ModSecurity with OWASP CRS provides automatic protection against SQLi, XSS, LFI, RFI, and more.

---

## 22. gRPC / HTTP/2 Hardening
**Purpose:** Secure modern protocols to avoid protocol-specific exploits.
```nginx
http2_max_concurrent_streams 128;
http2_max_header_size 16k;
http2_max_field_size 4k;
```

---

## 23. Connection Limits
**Purpose:** Prevent a single client from monopolizing connections.
```nginx
limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;
limit_conn conn_limit_per_ip 10;
```

---

## 24. Timeout Optimization
**Purpose:** Mitigate slowloris attacks.
```nginx
client_body_timeout 10s;
client_header_timeout 10s;
keepalive_timeout 15s;
send_timeout 10s;
```

---

## 25. Separate Error Logging for Suspicious Requests
**Purpose:** Isolate and monitor malicious activity.
```nginx
error_log /var/log/nginx/suspicious.log warn;
```
> This file can be monitored by Fail2ban or sent to Loki for alerts.

---

## 26. JSON Structured Logging
**Purpose:** Easier parsing for SIEM tools.
```nginx
log_format json_combined escape=json
'{ "@timestamp": "$time_iso8601", '
'"remote_addr": "$remote_addr", '
'"request": "$request", '
'"status": $status, '
'"body_bytes_sent": $body_bytes_sent, '
'"http_referer": "$http_referer", '
'"http_user_agent": "$http_user_agent" }';

access_log /var/log/nginx/access.json json_combined;
```

---

## 27. mTLS (Mutual TLS Authentication)
**Purpose:** Require client certificates for sensitive APIs.
```nginx
ssl_verify_client on;
ssl_client_certificate /etc/nginx/ssl/ca.crt;
```

---

## 28. OCSP Stapling
**Purpose:** Speed up TLS handshakes and improve certificate validation security.
```nginx
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8;
```

---

## 29. ETag and Server Header Removal
**Purpose:** Avoid leaking server information.
```nginx
etag off;
more_clear_headers 'Server';
```
(Requires `ngx_headers_more` module)

---

## 30. Zero Trust Segmentation
**Purpose:** Restrict service-to-service communication using Nginx upstream rules + Docker network isolation.
**Implementation:**
- Only expose public routes in `server {}` block.
- Use internal upstream blocks for backend services with `listen 127.0.0.1`.

---

**Final Note:** With these 30 security measures, Nginx is hardened against a wide range of attacks. Remember: Security is a continuous process — always monitor, update, and test.
