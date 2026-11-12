# SSH Tunnel
[中文](./README.md) | **English**

Establish a tunnel over SSH

[![GitHub Stars](https://img.shields.io/github/stars/AbnerSC/ssh-tunnel-go?style=flat&label=Stars)](https://github.com/AbnerSC/ssh-tunnel-go/stargazers)
[![Docker Pulls](https://img.shields.io/docker/pulls/babyfly/ssh-tunnel?label=Docker%20Pulls)](https://hub.docker.com/r/babyfly/ssh-tunnel)

***GitHub***: [https://github.com/AbnerSC/ssh-tunnel-go.git](https://github.com/AbnerSC/ssh-tunnel-go.git)

### Go 1.27.3

### Dependencies
- [domain-list-community](https://github.com/v2fly/domain-list-community.git) 

### Run with Docker
```yaml
services:
  ssh-tunnel:
    image: babyfly/ssh-tunnel:latest
    container_name: ssh-tunnel
    restart: unless-stopped
    environment:
      - TZ=Asia/Shanghai
      - SOCKS_PORT=6666
      - HTTP_PORT=6667
      - SOCKS_USER=socks_user     # proxy account
      - SOCKS_PASSWORD=socks_pwd  # proxy password
      - SSH_SERVER=root@1.2.3.4   # server address and account
      - SSH_PORT=22               # server SSH port
      - SSH_PASSWORD=server_pwd   # server SSH password
      - DIRECT_IP=192.168.0.0/16,10.0.0.0/8,172.16.0.0/12
      - DIRECT_DOMAIN=localhost,fun,xyz,top # direct-connect domains
      - DIRECT_CN=true
      - FORCE_DOMAIN=googleapis.cn,google.cn,gstatic.cn # force-proxied domains
      - SSH_KNOWN_HOSTS=/app/logs/known_hosts
    ports:
      - 16666:6666
      - 16667:6667
    volumes:
      - ./logs:/app/logs
    mem_limit: 128m
```

- Environment variable reference:

| Environment variable   | Description                                                                                                                                                                                |
|------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `SOCKS_PORT`           | Local SOCKS5 listen port                                                                                                                                                                   |
| `HTTP_PORT`            | Local HTTP proxy listen port                                                                                                                                                               |
| `SOCKS_USER`           | Proxy account, shared by the SOCKS5 and HTTP proxies (optional)                                                                                                                            |
| `SOCKS_PASSWORD`       | Proxy password, shared by the SOCKS5 and HTTP proxies (optional)                                                                                                                           |
| `SSH_SERVER`           | Tunnel server address and account, e.g. `root@1.2.3.4` (optional). When empty, the local process serves the proxy directly                                                                |
| `SSH_PORT`             | Server SSH port (optional), configured together with `SSH_SERVER`                                                                                                                          |
| `SSH_PASSWORD`         | Server SSH password (optional), configured together with `SSH_SERVER`                                                                                                                      |
| `SSH_POOL`             | SSH connection pool size (optional); leaving it unset is recommended, the default is already optimal                                                                                       |
| `DIRECT_IP`            | Direct-connect IPs/CIDR ranges (multiple values separated by commas or spaces, optional)                                                                                                   |
| `DIRECT_DOMAIN`        | Direct-connect domains, matched against the registrable (apex) domain (comma- or space-separated, optional)                                                                                |
| `DIRECT_CN`            | Route all Chinese domains directly; set to `true` to enable the default `cn` list, or specify geosite names directly (e.g. `cn,private`) (optional)                                        |
| `FORCE_DOMAIN`         | Domains forced through the SSH tunnel (apex-domain match), taking priority over all direct-connect rules (optional)                                                                        |
| `BIND_ADDR`            | Listen address for the proxy ports, defaults to `0.0.0.0`; set `127.0.0.1` to restrict access to the local machine (optional)                                                              |
| `ALLOW_UNAUTH_PUBLIC`  | Allow serving an **unauthenticated** proxy on a non-loopback address, defaults to `false`                                                                                                  |
| `MAX_CONNS`            | Global concurrent connection limit for the proxies (shared quota between SOCKS5 and HTTP), defaults to `256`; `0` means unlimited (optional)                                                |
| `MAX_CONNS_PER_IP`     | Concurrent connection limit per source IP, defaults to `32`; `0` means unlimited; must not exceed `MAX_CONNS` (optional)                                                                   |
| `IDLE_TIMEOUT`         | Close a relayed connection after this much bidirectional silence, reclaiming zombie connections left by sleeping/offline clients; defaults to `30m`, accepts `30m`/`1800` (seconds), `0` or `off` disables (optional) |
| `SSH_KNOWN_HOSTS`      | Server host key record file, defaults to `known_hosts` in the working directory (`/app/logs/known_hosts` inside the container) (optional)                                                  |
| `SSH_HOST_KEY`         | Pinned server host key fingerprint (`SHA256:...`), may be passed repeatedly or comma-separated; when set, only matching fingerprints are accepted (optional)                               |
| `CIPHER_MASTER_KEY`    | DES3 master key, shared by `-encode` encryption and decryption at startup; falls back to the built-in default key when unset. For high-security deployments, inject a custom value via docker secrets / K8s Secret so the default key in the source is never used |

### Deployment Notes (Security)

1. **Proxy authentication must be configured in pairs**. `SOCKS_USER` and `SOCKS_PASSWORD` need to be set **together**; configuring only one causes startup to fail immediately.
2. **Unauthenticated proxies may not listen externally**. If no authentication is configured and `BIND_ADDR` is not a loopback address, the process refuses to start. Choose one of: configure full authentication; set `BIND_ADDR=127.0.0.1` (local machine / co-located containers only); or explicitly set `ALLOW_UNAUTH_PUBLIC=true` after confirming network isolation.
3. **SSH host keys use trust-on-first-use (TOFU) by default**. The server fingerprint is written to `SSH_KNOWN_HOSTS` on the first connection (defaults to `/app/logs/known_hosts` inside the container; move it to a mounted writable directory for persistence, otherwise every container rebuild requires re-trusting), and later fingerprint changes cause connections to be rejected with a "host key changed" error; in production, pin the fingerprint with `SSH_HOST_KEY`:
4. **Authentication failures are rate-limited and banned**. 10 failures from the same source IP within 1 minute result in a 5-minute ban.
5. **Connection limits determine memory usage**. Defaults are 256 global / 32 per source IP (SOCKS5 and HTTP share the quota), requiring about 64MB; lower `MAX_CONNS` when memory is tight, `0` means unlimited (not recommended).
6. **The container runs as non-root** (uid 10001, only `ca-certificates` installed); listening on ports below 1024 requires `--cap-add=NET_BIND_SERVICE` or switching to a high port.

### Usage Tests

```bash
# with account and password configured
curl -x http://socks_user:socks_pwd@127.0.0.1:6667 https://www.google.com
curl -x socks5h://socks_user:socks_pwd@127.0.0.1:6666 https://www.google.com

# without account and password (only when BIND_ADDR=127.0.0.1 or ALLOW_UNAUTH_PUBLIC=true)
curl -x http://127.0.0.1:6667 https://www.google.com
```

### Features
- [X] Establish a tunnel through a remote SSH proxy
- [X] SOCKS5 proxy support
- [X] HTTP proxy support
- [X] Serve the proxy locally without going through a remote SSH proxy (omitting `-server` enables local proxy mode)
- [X] Direct-connect IP configuration (supports IPs and CIDR ranges); direct-connect IPs are accessed locally without going through the remote SSH proxy (`-direct-ip`, supports CIDR and dotted-netmask notation)
- [X] Direct-connect domain configuration (apex-domain matching); direct-connect domains are accessed locally without going through the remote SSH proxy (`-direct-domain`)
- [X] Built-in geosite data (`dlc.dat`); `-direct-cn` enables direct connection for all Chinese domains in one switch (other geosite lists can also be specified)
- [X] Force-through-tunnel domain configuration (`-force-domain`) to counteract false positives from direct-connect rules (e.g. `geosite:cn` including `googleapis.cn` breaks Google Play updates)
- [X] SOCKS5 supports IPv6 destination addresses (for dual-stack Android clients that prefer AAAA resolution, e.g. Google Play downloads); requires the tunnel server to have IPv6 egress
- [X] Periodic statistics logging (active/cumulative connection counts and upstream/downstream bytes every 5 minutes); per-connection logging can be enabled with `LOG_LEVEL=debug`
- [X] Two-dimensional concurrent connection limits (defaults: 256 global / 32 per IP, shared quota between SOCKS5 and HTTP, adjustable via `MAX_CONNS` / `MAX_CONNS_PER_IP`, `0` means unlimited); connections over the limit are closed directly
- [X] Idle connection reclamation (closes after 30 minutes of bidirectional silence by default, adjustable via `IDLE_TIMEOUT`, `0` disables), so zombie connections from sleeping/offline clients cannot hold concurrent slots and SSH channels forever
- [X] Exponential backoff on SSH session reconnect (starting at 5s, capped at 60s, staggered per slot), avoiding handshake storms and log flooding when the server is unavailable
- [X] HTTP proxy compatible with Java ecosystem clients (Apache HttpClient / Jetty HttpClient / java.net.http.HttpClient)

### Compatibility Verified
- [X] v2rayN (Windows)
- [X] v2rayNG (Android)
- [X] Google Chrome
- [X] Google Play (Android)
- [X] Gitea (Docker environment variables)
- [X] Nexus3 (HTTP proxy configured in-app)
- [X] Linux (OpenEuler)
- [X] Windows 10/11
- [X] Android 16
