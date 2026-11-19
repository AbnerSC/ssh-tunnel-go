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

      # ===== Proxy ports and authentication =====
      - SOCKS_PORT=6666                 # local SOCKS5 listen port
      - HTTP_PORT=6667                  # local HTTP proxy listen port (delete if unused)
      - SOCKS_USER=socks_user           # proxy account, shared by SOCKS5/HTTP
      - SOCKS_PASSWORD=socks_pwd        # proxy password; must be set together with the account, otherwise startup fails
      - BIND_ADDR=0.0.0.0               # listen address; use 127.0.0.1 for local-only access
      - ALLOW_UNAUTH_PUBLIC=false       # allow an unauthenticated proxy on a public listen address (default false)
      - MAX_CONNS=256                   # global connection limit, 0 = unlimited
      - MAX_CONNS_PER_IP=32             # per-IP connection limit, 0 = unlimited, must not exceed MAX_CONNS
      - IDLE_TIMEOUT=30m                # reclaim a connection after this much silence; 30m/1800(seconds)/off

      # ===== SSH tunnel server (leave SSH_SERVER empty for a local-only proxy) =====
      - SSH_SERVER=root@1.2.3.4         # server address and account
      - SSH_PORT=22                     # server SSH port
      - SSH_PASSWORD=server_pwd         # server SSH password
      - SSH_POOL=8                      # SSH connection pool size, default 8, usually no need to change
      - SSH_KNOWN_HOSTS=/app/logs/known_hosts # host key record file (persisted via the mounted volume)
      - SSH_HOST_KEY=                   # pinned host key fingerprint SHA256:..., comma-separated

      # ===== Direct / tunnel routing rules =====
      - DIRECT_IP=192.168.0.0/16,10.0.0.0/8,172.16.0.0/12 # direct IPs/CIDRs
      - DIRECT_DOMAIN=localhost,fun,xyz,top                # direct domains (apex-domain match)
      - DIRECT_CN=true                                     # route all Chinese domains directly; geosite names such as cn,private also work
      - FORCE_DOMAIN=googleapis.cn,google.cn,gstatic.cn    # force through the tunnel, takes priority over all direct rules

      # ===== Logging and encryption =====
      - LOG_FORMAT=json                 # log format: json (default) / text
      - LOG_LEVEL=info                  # log level: debug/info (default)/warn/error
      - CIPHER_MASTER_KEY=              # DES3 master key; falls back to the built-in default when empty

      # ===== TUN global takeover (optional, off by default; see the note below) =====
      # - TUN_MODE=1                            # enable global takeover
      # - TUN_CONFIG=/app/logs/tun.json         # generated config path; empty means a temp file
      # - TUN_UDP_POLICY=direct                 # other UDP policy: direct (default) / block
      # - TUN_FAKEIP=true                       # fake-IP for proxied domains, default true
      # - TUN_DNS_PROXY=tcp://8.8.8.8           # DNS resolved through the tunnel
      # - TUN_DNS_CN=udp://223.5.5.5            # DNS for direct resolution of Chinese domains
      # - TUN_ROUTE_EXCLUDE=                    # extra CIDRs kept out of the TUN route, comma-separated
      # - TUN_STACK=gvisor                      # gvisor (default) / system / mixed
      # - TUN_LOG_LEVEL=warn                    # sing-box log level
      # - TUN_AUTO_REDIRECT=false               # Linux-only nftables acceleration
    ports:
      - 16666:6666
      - 16667:6667
    volumes:
      - ./logs:/app/logs
    mem_limit: 128m
```

> Enabling TUN inside the container requires host networking: additionally set `network_mode: host`, `user: "0"`, `cap_add: [NET_ADMIN]`, `devices: ["/dev/net/tun"]`; the image already ships the sing-box binary for its architecture (`/app/singbox`), so nothing needs to be installed or mounted; with host networking the `ports` mappings no longer apply. See the full Docker Compose example at the end of the “Global Takeover (TUN Mode)” section below.

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
| `SSH_KNOWN_HOSTS`      | Server host key record file, defaults to `known_hosts` in the working directory (`/app/known_hosts` inside the container; the example moves it to the mounted `/app/logs/known_hosts` for persistence) (optional)                        |
| `SSH_HOST_KEY`         | Pinned server host key fingerprint (`SHA256:...`), may be passed repeatedly or comma-separated; when set, only matching fingerprints are accepted (optional)                               |
| `CIPHER_MASTER_KEY`    | DES3 master key, shared by `-encode` encryption and decryption at startup; falls back to the built-in default key when unset. For high-security deployments, inject a custom value via docker secrets / K8s Secret so the default key in the source is never used |
| `TUN_MODE` etc.        | Optional global takeover (TUN mode), opt-in; see the “Global Takeover (TUN Mode)” section below |

### Deployment Notes (Security)

1. **Proxy authentication must be configured in pairs**. `SOCKS_USER` and `SOCKS_PASSWORD` need to be set **together**; configuring only one causes startup to fail immediately.
2. **Unauthenticated proxies may not listen externally**. If no authentication is configured and `BIND_ADDR` is not a loopback address, the process refuses to start. Choose one of: configure full authentication; set `BIND_ADDR=127.0.0.1` (local machine / co-located containers only); or explicitly set `ALLOW_UNAUTH_PUBLIC=true` after confirming network isolation.
3. **SSH host keys use trust-on-first-use (TOFU) by default**. The server fingerprint is written to `SSH_KNOWN_HOSTS` on the first connection (defaults to `/app/known_hosts` inside the container; move it to a mounted writable directory for persistence, otherwise every container rebuild requires re-trusting), and later fingerprint changes cause connections to be rejected with a "host key changed" error; in production, pin the fingerprint with `SSH_HOST_KEY`:
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

### Global Takeover (TUN Mode)

Optional. With `TUN_MODE=1` the process generates a [sing-box](https://sing-box.sagernet.org) configuration and supervises it as a child process, taking over **all system traffic** through a TUN interface; the existing SOCKS5/HTTP proxies keep listening and behave exactly as before.

```
application traffic -> TUN interface -> sing-box routing
    |-- Chinese domains / private networks / DIRECT_IP --> direct (local)
    |-- everything else (TCP) --> local SOCKS5 -> SSH tunnel -> remote
    |-- DNS port 53 --> hijacked: Chinese domains resolved locally, others via TCP DNS through the tunnel
    |-- UDP 443 (QUIC) --> rejected for non-direct destinations, browsers fall back to TCP through the tunnel
    '-- other UDP --> direct by default (TUN_UDP_POLICY=block to reject)
```

- **Prerequisites**
  - Linux only, root or `CAP_NET_ADMIN`, and `/dev/net/tun` must exist; starting TUN mode on any other platform fails fast
  - sing-box **>= 1.12** is shipped with the program: `/app/singbox` in the image (the build only copies the file for the target architecture); for a plain binary deployment put `singbox` next to the executable (or install it into `PATH`)
  - TUN mode requires `SOCKS_PORT` (startup fails without it); without `SSH_SERVER` global traffic has no tunnel egress (equivalent to a direct connection)
- **TUN-specific environment variables** (each has a matching `-tun-*` flag)

| Environment variable | Default | Description |
|---|---|---|
| `TUN_MODE` | off | `true/1/yes/on` enables global takeover (`-tun`) |
| `TUN_CONFIG` | auto-generated temp file | output path for the sing-box config; when unset a random `ssh-tunnel-tun-*.json` is created in the system temp dir (contains plaintext credentials and is deleted on exit); when set it is kept for troubleshooting (`-tun-config`) |
| `TUN_UDP_POLICY` | `direct` | UDP other than DNS/QUIC: `direct` allows it, `block` rejects it (`-tun-udp-policy`) |
| `TUN_FAKEIP` | `true` | return fake-IPs for proxied domains so domain routing stays accurate; `false` falls back to SNI sniffing (`-tun-fakeip`) |
| `TUN_DNS_PROXY` | `tcp://8.8.8.8` | DNS resolved through the proxy; supports `tcp://`, `udp://`, `tls://`, `https://` (`-tun-dns-proxy`) |
| `TUN_DNS_CN` | `udp://223.5.5.5` | DNS for direct resolution of Chinese domains (`-tun-dns-cn`) |
| `TUN_ROUTE_EXCLUDE` | empty | extra CIDRs kept out of the TUN route (comma-separated); the SSH server address is added automatically; directly-attached interface subnets are excluded automatically (see "Known limitation" below) (`-tun-route-exclude`) |
| `TUN_STACK` | `gvisor` | `gvisor`/`system`/`mixed` (`-tun-stack`) |
| `TUN_LOG_LEVEL` | `warn` | sing-box log level, forwarded into the process log (`-tun-log-level`) |
| `TUN_AUTO_REDIRECT` | `false` | Linux-only nftables acceleration (`-tun-auto-redirect`) |

- sing-box notes
  - The binary is no longer embedded in the Go program: the Docker build copies only `core/sing-box-<arch>` for the target architecture and renames it to `/app/singbox`, and the program always looks for that fixed file name, so no CPU-architecture branching is needed
  - For a plain (non-image) deployment, take the matching file from `core/`, rename it to `singbox` and place it next to the executable; the program also falls back to `PATH`
  - Before starting TUN the program runs `singbox version` and refuses to start below **1.12**; no in-program download/update

- Domain routing reuses the embedded `dlc.dat`: the `cn` list is enabled by default in TUN mode unless `DIRECT_CN` is set explicitly (**TUN entry only**; applications explicitly pointed at the SOCKS5/HTTP ports keep the original proxy rules, so set `DIRECT_CN=true` if both entries should behave the same); `FORCE_DOMAIN` has the highest priority; `DIRECT_IP`/`DIRECT_DOMAIN` apply as well
- Three layers of loop prevention: the ssh-tunnel process itself, the SSH server IP and private CIDRs are always routed directly, so proxy → TUN → proxy loops cannot happen
- LAN coexistence (automatic): subnets directly attached to each interface (LAN, docker bridges, the VPS public subnet) are added to `route_exclude_address`, so return traffic for inbound connections served by this host (SSH/Web, etc.) never enters the TUN and cannot be RST'd by the userspace stack; consequently **TUN never proxies targets inside the host's own subnets**
- Known limitation: to keep DNS hijacking and fake-IP working, the system DNS server address is carved out of those subnets (prefix split), which means **all traffic to and from that DNS address** (not only port 53) still goes through the TUN, and its inbound connections to this host are not protected. If that host also provides services you need to reach directly (e.g. SSH/SMB on a router/NAS), add its address to `TUN_ROUTE_EXCLUDE` explicitly (trade-off: that DNS is no longer hijacked; use `TUN_DNS_CN` or the system resolver instead); when the system DNS is a loopback address (systemd-resolved `127.0.0.53`, Docker `127.0.0.11`) hijacking does not take effect at all and a warning is logged at startup

**Linux example**

```bash
# Prerequisites: Linux; root or CAP_NET_ADMIN; /dev/net/tun; singbox next to ssh-tunnel (already included in the image)
sudo TUN_MODE=1 SOCKS_PORT=6666 DIRECT_CN=true MAX_CONNS=1024 MAX_CONNS_PER_IP=0 SSH_POOL=16 \
     SSH_SERVER=root@1.2.3.4 SSH_PASSWORD=****** ./ssh-tunnel

# Verify: "ip route | grep ssh-tun" shows the default-route takeover; curl ifconfig.me returns the server egress IP
```

Key systemd unit snippet:

```ini
[Service]
Environment=TUN_MODE=1 SOCKS_PORT=6666 DIRECT_CN=true MAX_CONNS=1024 MAX_CONNS_PER_IP=0
Environment=SSH_SERVER=root@1.2.3.4 SSH_PASSWORD=******
ExecStart=/opt/ssh-tunnel/ssh-tunnel
Restart=on-failure
```

Docker Compose (when TUN must cover the host network; Linux hosts only):

```yaml
services:
  ssh-tunnel:
    image: babyfly/ssh-tunnel:latest
    container_name: ssh-tunnel
    restart: unless-stopped
    # Global takeover must share the host network; with host networking the ports mappings no longer apply (nor are they needed)
    network_mode: host
    # The image runs as non-root (uid 10001) by default; creating a TUN device requires root
    user: "0"
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun
    environment:
      - TZ=Asia/Shanghai

      # ===== TUN and the local SOCKS egress (required) =====
      - TUN_MODE=1                      # enable global takeover
      - SOCKS_PORT=6666                 # the only egress for TUN; startup fails without it
      # - HTTP_PORT=6667                # optional: keep the HTTP proxy port as well
      - BIND_ADDR=127.0.0.1             # loopback only, avoiding a self-referencing loop for the socks egress
      - MAX_CONNS=1024                  # all traffic now goes through SOCKS, raise this limit
      - MAX_CONNS_PER_IP=0              # TUN traffic always comes from 127.0.0.1, so a per-IP limit caps the whole machine
      - IDLE_TIMEOUT=30m                # reclaim zombie connections after this much silence (default 30m, 0/off disables)
      # - SOCKS_USER=tun_user           # authentication is optional on loopback; recommended on multi-user hosts
      # - SOCKS_PASSWORD=tun_pwd

      # ===== SSH tunnel server =====
      - SSH_SERVER=root@1.2.3.4         # server address and account; when empty global traffic equals a direct connection
      - SSH_PORT=22                     # server SSH port
      - SSH_PASSWORD=server_pwd         # server SSH password
      - SSH_POOL=16                     # more concurrency after global takeover; a slightly larger pool helps
      - SSH_KNOWN_HOSTS=/app/logs/known_hosts # host key record file (persisted via the mounted volume)
      # - SSH_HOST_KEY=SHA256:xxxx      # pinning the host key fingerprint is recommended in production

      # ===== Routing rules =====
      - DIRECT_CN=true                  # Chinese domains direct; TUN also enables the cn list by default when unset
      - DIRECT_IP=192.168.0.0/16,10.0.0.0/8,172.16.0.0/12 # direct IPs/CIDRs
      - DIRECT_DOMAIN=localhost,fun,xyz,top                # direct domains (apex-domain match)
      - FORCE_DOMAIN=googleapis.cn,google.cn,gstatic.cn    # force through the tunnel, takes priority over all direct rules

      # ===== TUN details (defaults shown, adjust as needed) =====
      - TUN_STACK=gvisor                # gvisor (default) / system / mixed
      - TUN_UDP_POLICY=direct           # other UDP: direct (default) / block
      - TUN_FAKEIP=true                 # fake-IP for proxied domains, default true
      - TUN_DNS_PROXY=tcp://8.8.8.8     # DNS resolved through the tunnel
      - TUN_DNS_CN=udp://223.5.5.5      # DNS for direct resolution of Chinese domains
      - TUN_ROUTE_EXCLUDE=              # extra CIDRs kept out of the TUN route, comma-separated; the SSH server address is always excluded
      - TUN_LOG_LEVEL=warn              # sing-box log level, set debug when troubleshooting
      # - TUN_CONFIG=/app/logs/tun.json # keep the generated config for debugging (contains plaintext credentials; delete afterwards)
      # - TUN_AUTO_REDIRECT=false       # Linux-only nftables acceleration, opt-in

      # ===== Logging and encryption =====
      - LOG_FORMAT=json                 # log format: json (default) / text
      - LOG_LEVEL=info                  # log level: debug/info (default)/warn/error
      # - CIPHER_MASTER_KEY=            # DES3 master key; -encode and the service must use the same value
    volumes:
      - ./logs:/app/logs
    # Raise memory together with the connection limit: 1024 connections need about 256MB (256 need about 64MB)
    mem_limit: 512m
```

> Notes:
> - TUN can only take over a **Linux host** network; on Docker Desktop (Windows/macOS) host networking points at the VM, so TUN mode is unavailable on those platforms.
> - With `network_mode: host` the `ports` mappings no longer apply; SOCKS5/HTTP ports listen directly on the host, and `BIND_ADDR=127.0.0.1` keeps them local-only.
> - The image ships sing-box for its own architecture (`/app/singbox`): TUN mode calls it directly, with no network access or extra mounts required; images for other architectures (e.g. armv7) do not include sing-box, so TUN mode is unavailable there.
> - Running with `user: "0"` means log files and `known_hosts` created under the mounted `./logs` are owned by root.
> - Verify: `ip route | grep ssh-tun` on the host shows the default route, and `curl ifconfig.me` returns the server egress IP.

- **UDP / DNS behaviour**

| Traffic | Handling |
|---|---|
| DNS port 53 | hijacked into the built-in DNS: Chinese domains resolved directly, others through TCP DNS inside the tunnel, preventing DNS leaks; internal domains (`.local`/`.lan`, etc.) use the system resolver |
| UDP 443 (QUIC) | rejected for all non-direct destinations; browsers fall back to TCP through the tunnel immediately, avoiding split IPs caused by direct QUIC; private networks and `DIRECT_IP` targets keep QUIC on the direct path |
| other UDP | allowed directly by default (same as without TUN, keeps WebRTC/games working); `TUN_UDP_POLICY=block` rejects all of it |
| application-level DoH | goes through TCP 443 inside the tunnel (routing rules do not apply but connectivity is kept); consider disabling DoH in Firefox and similar browsers |

- **Troubleshooting**
  - Inspect the generated config: by default a random `ssh-tunnel-tun-*.json` in the system temp dir, deleted when the process exits; set `TUN_CONFIG` to a fixed path to keep it
  - sing-box output is forwarded line by line into the process log; set `TUN_LOG_LEVEL=debug` to debug routing
  - “sing-box not found (singbox)”: rename the sing-box binary for the matching architecture to `singbox` and place it next to the executable (the image already provides `/app/singbox`), or install it into `PATH`
  - sing-box execution failures: the log shows the path and reason; check that the file is executable and that its version is >= 1.12
  - If sing-box crashes, the main process logs the error and exits with code 1; rely on systemd `Restart=on-failure` / Docker `restart: unless-stopped` to recover
  - Stopping the program restores system networking: a SIGTERM is sent so sing-box cleans up routes/interfaces itself (forced kill after 5s)

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
- [X] Optional global takeover via TUN (`TUN_MODE=1`): a supervised sing-box child process routes all system traffic into the local SOCKS5 proxy, with DNS hijacking, direct routing for Chinese domains/private networks and QUIC fallback; behaviour is identical to pure proxy mode when disabled
- [X] Bundled sing-box (linux/amd64, linux/arm64): the image only includes the file for its own architecture, renamed to `singbox`, so no downloads or manual installation are required

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
