# SSH隧道
[English](./README-en.md) | **中文**

通过SSH建立一个隧道

[![GitHub Stars](https://img.shields.io/github/stars/AbnerSC/ssh-tunnel-go?style=flat&label=Stars)](https://github.com/AbnerSC/ssh-tunnel-go/stargazers)
[![Docker Pulls](https://img.shields.io/docker/pulls/babyfly/ssh-tunnel?label=Docker%20Pulls)](https://hub.docker.com/r/babyfly/ssh-tunnel)

***GitHub***：[https://github.com/AbnerSC/ssh-tunnel-go.git](https://github.com/AbnerSC/ssh-tunnel-go.git)

### Go 1.27.3

### 依赖
- [domain-list-community](https://github.com/v2fly/domain-list-community.git) 

### Docker 运行
```yaml
services:
  ssh-tunnel:
    image: babyfly/ssh-tunnel:latest
    container_name: ssh-tunnel
    restart: unless-stopped
    environment:
      - TZ=Asia/Shanghai

      # ===== 代理端口与认证 =====
      - SOCKS_PORT=6666                 # 本地socks5监听端口
      - HTTP_PORT=6667                  # 本地http代理监听端口（不需要可删除）
      - SOCKS_USER=socks_user           # 代理账号，socks5/http共用
      - SOCKS_PASSWORD=socks_pwd        # 代理密码，必须与账号同时配置，只配一个会启动失败
      - BIND_ADDR=0.0.0.0               # 监听地址；仅本机使用改 127.0.0.1
      - ALLOW_UNAUTH_PUBLIC=false       # 无认证时是否允许对外监听，默认 false（拒绝启动）
      - MAX_CONNS=256                   # 全局并发连接上限，0 不限制
      - MAX_CONNS_PER_IP=32             # 单IP并发上限，0 不限制，不得大于 MAX_CONNS
      - IDLE_TIMEOUT=30m                # 双向静默超时即回收连接，30m/1800(秒)/off

      # ===== SSH隧道服务端（SSH_SERVER 留空则为纯本地代理）=====
      - SSH_SERVER=root@1.2.3.4         # 服务器地址与账号
      - SSH_PORT=22                     # 服务器SSH端口
      - SSH_PASSWORD=server_pwd         # 服务器SSH密码
      - SSH_POOL=8                      # SSH连接池大小，默认 8，一般无需修改
      - SSH_KNOWN_HOSTS=/app/logs/known_hosts # 主机密钥记录文件（挂载后持久化）
      - SSH_HOST_KEY=                   # 固定主机密钥指纹 SHA256:...，多个用逗号分隔

      # ===== 直连/隧道分流规则 =====
      - DIRECT_IP=192.168.0.0/16,10.0.0.0/8,172.16.0.0/12 # 直连IP/网段
      - DIRECT_DOMAIN=localhost,fun,xyz,top                # 直连域名（主域匹配）
      - DIRECT_CN=true                                     # 国内域名全量直连，也可写 cn,private
      - FORCE_DOMAIN=googleapis.cn,google.cn,gstatic.cn    # 强制走隧道，优先于全部直连规则

      # ===== 日志与加密 =====
      - LOG_FORMAT=json                 # 日志格式：json（默认）/ text
      - LOG_LEVEL=info                  # 日志级别：debug/info（默认）/warn/error
      - CIPHER_MASTER_KEY=              # DES3主密钥，留空用内置默认值；建议自定义

      # ===== TUN全局接管（可选，默认关闭，开启条件见下方说明）=====
      # - TUN_MODE=1                            # 开启全局接管
      # - TUN_CONFIG=/app/logs/tun.json         # 生成的配置路径，留空为临时文件
      # - TUN_UDP_POLICY=direct                 # 其余UDP策略：direct（默认）/block
      # - TUN_FAKEIP=true                       # 被代理域名返回fake-ip，默认 true
      # - TUN_DNS_PROXY=tcp://8.8.8.8           # 走隧道的DNS
      # - TUN_DNS_CN=udp://223.5.5.5            # 国内域名直连解析DNS
      # - TUN_ROUTE_EXCLUDE=                    # 额外不进TUN的网段，逗号分隔
      # - TUN_STACK=gvisor                      # gvisor（默认）/system/mixed
      # - TUN_LOG_LEVEL=warn                    # sing-box日志级别
      # - TUN_AUTO_REDIRECT=false               # Linux专属nftables加速
    ports:
      - 16666:6666
      - 16667:6667
    volumes:
      - ./logs:/app/logs
    mem_limit: 128m
```

> 容器内启用 TUN 需作用于宿主机网络：另加 `network_mode: host`、`user: "0"`、`cap_add: [NET_ADMIN]`、`devices: ["/dev/net/tun"]`；镜像已内置对应架构的 sing-box（`/app/singbox`），无需额外安装或挂载；host 网络下 `ports` 映射失效。完整示例见下文「全局接管（TUN 模式）」章节末尾的 Docker Compose 示例。

- 环境变量说明：

| 环境变量               | 说明                                                                                                                                                                                       |
|------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `SOCKS_PORT`           | 本地socks5监听端口                                                                                                                                                                         |
| `HTTP_PORT`            | 本地http代理监听端口                                                                                                                                                                       |
| `SOCKS_USER`           | 代理账号，socks5 与 http 代理共用（可选）                                                                                                                                                  |
| `SOCKS_PASSWORD`       | 代理密码，socks5 与 http 代理共用（可选）                                                                                                                                                  |
| `SSH_SERVER`           | 隧道服务器地址与账号，如 `root@1.2.3.4`（可选）当为空时，默认本机直接提供代理                                                                                                              |
| `SSH_PORT`             | 服务器SSH端口（可选）,跟随`SSH_SERVER`一起配置                                                                                                                                             |
| `SSH_PASSWORD`         | 服务器SSH密码（可选）,跟随`SSH_SERVER`一起配置                                                                                                                                             |
| `SSH_POOL`             | SSH 连接池大小（可选），建议不配置，默认配置已最优                                                                                                                                         |
| `DIRECT_IP`            | 直连IP/网段（逗号或空格分隔多个值，可选）                                                                                                                                                  |
| `DIRECT_DOMAIN`        | 直连域名，匹配主域名（逗号或空格分隔，可选）                                                                                                                                               |
| `DIRECT_CN`            | 中国域名全量直连，取值 `true` 启用默认 `cn` 列表，也可直接写 geosite 名(如 `cn,private`，可选)                                                                                             |
| `FORCE_DOMAIN`         | 强制走 SSH 隧道的域名（主域匹配），优先级高于全部直连规则（可选）                                                                                                                          |
| `BIND_ADDR`            | 代理端口的监听地址，默认 `0.0.0.0`；设 `127.0.0.1` 则仅本机可用（可选）                                                                                                        |
| `ALLOW_UNAUTH_PUBLIC`  | 允许在非回环地址上提供**无认证**代理，默认 `false`                                                                                                                       |
| `MAX_CONNS`            | 代理并发连接上限（全局，SOCKS5 与 HTTP 共享配额），默认 `256`，`0` 表示不限制（可选）                                                                                                      |
| `MAX_CONNS_PER_IP`     | 单来源 IP 的并发连接上限，默认 `32`，`0` 表示不限制；不得大于 `MAX_CONNS`（可选）                                                                                                          |
| `IDLE_TIMEOUT`         | 转发阶段双向静默超过该时长即关闭连接，用于回收客户端休眠/掉线留下的僵尸连接；默认 `30m`，支持 `30m`/`1800`（秒）写法，`0` 或 `off` 表示不回收（可选）                                      |
| `SSH_KNOWN_HOSTS`      | 服务端主机密钥记录文件，默认工作目录下的 `known_hosts`（容器内为 `/app/known_hosts`，示例改到挂载的 `/app/logs/known_hosts` 便于持久化）（可选）                                                                                                      |
| `SSH_HOST_KEY`         | 固定服务端主机密钥指纹（`SHA256:...`），可重复传参或逗号分隔多个；设置后只接受匹配的指纹 （可选）                                                                                                  |
| `CIPHER_MASTER_KEY`    | DES3 密文主密钥，-encode 加密与启动解密共用；未设置时回退内置默认密钥。高安全部署建议通过 docker secrets / K8s Secret 注入自定义值，让源码里的默认密钥不参与加解密 |
| `TUN_MODE` 等 TUN 参数 | 可选全局接管（TUN 模式），按需开启，见下文「全局接管（TUN 模式）」章节 |

### 部署须知（安全）

1. **代理认证必须成对配置**。`SOCKS_USER` 与 `SOCKS_PASSWORD` 需要**同时**配置，只配其中一个会直接启动失败。
2. **无认证不允许对外监听**。未配认证且 `BIND_ADDR` 不是回环地址时进程拒绝启动，三选一：配齐认证；设 `BIND_ADDR=127.0.0.1`（仅本机/同机容器）；确认网络隔离后显式设 `ALLOW_UNAUTH_PUBLIC=true`。
3. **SSH 主机密钥默认首次信任（TOFU）**。首次连接会把服务端指纹写入 `SSH_KNOWN_HOSTS`（容器内默认为 `/app/known_hosts`，建议改到已挂载的可写目录里持久化，否则每次重建都要重新信任），之后指纹变化会拒绝连接并报“主机密钥已变更”；生产环境建议用 `SSH_HOST_KEY` 固定指纹：
4. **认证失败会限速封禁**。同一来源 IP 1 分钟内失败 10 次即封禁 5 分钟。
5. **并发上限决定内存占用**。默认全局 `256`、单来源 IP `32`（SOCKS5 与 HTTP 共享配额），约需 64MB；内存紧张时调低 `MAX_CONNS`，`0` 表示不限制（不建议）。
6. **容器以非 root 运行**（uid 10001，只装 `ca-certificates`）；监听 1024 以下端口需 `--cap-add=NET_BIND_SERVICE` 或改用高位端口。

### 使用测试

```bash
# 已配置账号密码
curl -x http://socks_user:socks_pwd@127.0.0.1:6667 https://www.google.com
curl -x socks5h://socks_user:socks_pwd@127.0.0.1:6666 https://www.google.com

# 未配置账号密码（仅限 BIND_ADDR=127.0.0.1 或 ALLOW_UNAUTH_PUBLIC=true）
curl -x http://127.0.0.1:6667 https://www.google.com
```

### 全局接管（TUN 模式）

可选功能。设置 `TUN_MODE=1` 后，程序自动生成 [sing-box](https://sing-box.sagernet.org) 配置并托管其子进程，通过 TUN 虚拟网卡接管**操作系统全部流量**；原有 SOCKS5/HTTP 代理照常监听、行为不变。

```
应用流量 -> TUN 网卡 -> sing-box 分流
    |-- 国内域名 / 私网 / DIRECT_IP --> 本机直连
    |-- 其余 TCP --> 本地 SOCKS5 -> SSH 隧道 -> 远端
    |-- DNS 53 --> 劫持：国内域名本地解析，其余经隧道 TCP DNS 解析
    |-- UDP 443 (QUIC) --> 非直连目标拒绝，浏览器回退 TCP 走隧道
    '-- 其余 UDP --> 默认直连（TUN_UDP_POLICY=block 可拒绝）
```

- **前置条件**
  - 仅支持 Linux，root 或 `CAP_NET_ADMIN`，且 `/dev/net/tun` 可用；其它平台启动 TUN 模式会直接报错
  - sing-box **>= 1.12** 随程序提供：镜像内为 `/app/singbox`（构建时按目标架构只拷入对应文件）；自行部署二进制时需把 `singbox` 放在程序同目录（或安装到 `PATH`）
  - TUN 模式依赖 `SOCKS_PORT`（缺少会启动失败）；未配置 `SSH_SERVER` 时全局流量没有隧道出口，等同于本机直连
- **TUN 专用环境变量**（均有对应的 `-tun-*` 命令行参数）

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `TUN_MODE` | 关闭 | `true/1/yes/on` 开启全局接管（`-tun`） |
| `TUN_CONFIG` | 自动生成的临时文件 | sing-box 配置输出路径；未指定时在系统临时目录生成随机文件名的 `ssh-tunnel-tun-*.json`（含明文凭据，退出时自动删除），指定后保留便于排障（`-tun-config`） |
| `TUN_UDP_POLICY` | `direct` | 非 DNS/QUIC 的 UDP：`direct` 直连放行 / `block` 拒绝（`-tun-udp-policy`） |
| `TUN_FAKEIP` | `true` | 被代理域名返回 fake-ip，保证域名分流精准；`false` 回退 SNI 嗅探（`-tun-fakeip`） |
| `TUN_DNS_PROXY` | `tcp://8.8.8.8` | 走代理的 DNS，支持 `tcp://`、`udp://`、`tls://`、`https://`（`-tun-dns-proxy`） |
| `TUN_DNS_CN` | `udp://223.5.5.5` | 国内域名直连解析用的 DNS（`-tun-dns-cn`） |
| `TUN_ROUTE_EXCLUDE` | 空 | 追加不进 TUN 的网段（逗号分隔），SSH 服务器地址自动加入；网卡直连网段自动排除（见下方「已知边界」）（`-tun-route-exclude`） |
| `TUN_STACK` | `gvisor` | `gvisor`/`system`/`mixed`（`-tun-stack`） |
| `TUN_LOG_LEVEL` | `warn` | sing-box 日志级别，输出透传到程序日志（`-tun-log-level`） |
| `TUN_AUTO_REDIRECT` | `false` | Linux 专属 nftables 加速（`-tun-auto-redirect`） |

- sing-box 说明
  - 二进制不再嵌入 Go 程序：Docker 镜像构建时按目标架构只拷入 `core/sing-box-<arch>` 并统一命名为 `/app/singbox`，程序只按固定文件名查找，无需判断 CPU 架构
  - 自行部署（非镜像）时，从 `core/` 取对应架构的文件改名为 `singbox` 放在程序同目录即可；程序也会回退到 `PATH` 中查找
  - 启动 TUN 前会执行 `singbox version` 校验版本，不满足 **>= 1.12** 时直接报错；程序内不做下载/更新

- 域名分流复用内置 `dlc.dat`：`DIRECT_CN` 未显式配置时 TUN 层默认启用 `cn` 列表直连（该默认值**仅作用于 TUN 入口**，显式指向 SOCKS5/HTTP 端口的应用仍按原有规则走隧道；需要两个入口行为一致时显式设置 `DIRECT_CN=true`），`FORCE_DOMAIN` 优先级最高，`DIRECT_IP`/`DIRECT_DOMAIN` 同样生效
- 三层防回环：ssh-tunnel 自身进程、SSH 服务器 IP、私网段默认直连，避免 代理 → TUN → 代理 死循环
- 局域网共存（自动）：各网卡直连的网段（LAN、docker 网桥、VPS 公网子网）自动加入 `route_exclude_address`，本机作为服务端（SSH/Web 等）的入站回程不经过 TUN，避免 mid-stream 报文被用户态协议栈 RST 导致入站连接断开；因此 **TUN 不代理与宿主机同子网的目标**
- 已知边界：为保住 DNS 劫持与 fake-ip，系统 DNS 服务器地址会从上述网段中单独扣除（前缀拆分），这意味着**与该 DNS 地址之间的全部流量**（不仅是 53 端口）仍经 TUN，其主动访问本机的入站回程不受保护。若该主机同时提供需要直连的入站服务（如路由器/NAS 上的 SSH、SMB），把它的地址显式加入 `TUN_ROUTE_EXCLUDE`（代价：该 DNS 不再被劫持，必要时改用 `TUN_DNS_CN` 或系统解析）；系统 DNS 为回环地址（systemd-resolved 的 `127.0.0.53`、Docker 的 `127.0.0.11`）时劫持本身不生效，启动日志会给出提示

**Linux 示例**

```bash
# 前置：Linux；root 或 CAP_NET_ADMIN；/dev/net/tun 存在；singbox 与 ssh-tunnel 同目录（镜像内已内置）
sudo TUN_MODE=1 SOCKS_PORT=6666 DIRECT_CN=true MAX_CONNS=1024 MAX_CONNS_PER_IP=0 SSH_POOL=16 \
     SSH_SERVER=root@1.2.3.4 SSH_PASSWORD=****** ./ssh-tunnel

# 验证：ip route | grep ssh-tun 出现默认路由；curl ifconfig.me 返回服务器出口 IP
```

systemd 单元关键片段：

```ini
[Service]
Environment=TUN_MODE=1 SOCKS_PORT=6666 DIRECT_CN=true MAX_CONNS=1024 MAX_CONNS_PER_IP=0
Environment=SSH_SERVER=root@1.2.3.4 SSH_PASSWORD=******
ExecStart=/opt/ssh-tunnel/ssh-tunnel
Restart=on-failure
```

Docker Compose（TUN 需作用于宿主机网络时，仅 Linux 宿主机）：

```yaml
services:
  ssh-tunnel:
    image: babyfly/ssh-tunnel:latest
    container_name: ssh-tunnel
    restart: unless-stopped
    # 全局接管必须共享宿主机网络；host 网络下 ports 映射失效（也不需要）
    network_mode: host
    # 镜像默认以非 root（uid 10001）运行，创建 TUN 网卡需要 root 权限
    user: "0"
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun
    environment:
      - TZ=Asia/Shanghai

      # ===== TUN 与本地 SOCKS 出站（必填）=====
      - TUN_MODE=1                      # 开启全局接管
      - SOCKS_PORT=6666                 # TUN 的唯一出站，缺省会启动失败
      # - HTTP_PORT=6667                # 可选：同时保留 HTTP 代理端口
      - BIND_ADDR=127.0.0.1             # 仅监听回环，避免 socks 出站形成自指回环
      - MAX_CONNS=1024                  # 全局接管后流量全部经 SOCKS，建议调大
      - MAX_CONNS_PER_IP=0              # TUN 流量来源均为 127.0.0.1，不放开会变成整机并发上限
      - IDLE_TIMEOUT=30m                # 双向静默回收僵尸连接（默认 30m，0/off 不回收）
      # - SOCKS_USER=tun_user           # 回环监听可不配认证；同机多用户环境建议配置
      # - SOCKS_PASSWORD=tun_pwd

      # ===== SSH 隧道服务端 =====
      - SSH_SERVER=root@1.2.3.4         # 服务器地址与账号；留空则全局流量等于本机直连
      - SSH_PORT=22                     # 服务器SSH端口
      - SSH_PASSWORD=server_pwd         # 服务器SSH密码
      - SSH_POOL=16                     # 全局接管后并发升高，连接池可适当调大
      - SSH_KNOWN_HOSTS=/app/logs/known_hosts # 主机密钥记录文件（挂载后持久化）
      # - SSH_HOST_KEY=SHA256:xxxx      # 生产环境建议固定主机密钥指纹

      # ===== 分流规则 =====
      - DIRECT_CN=true                  # 国内域名直连；未配置时 TUN 层也默认启用 cn
      - DIRECT_IP=192.168.0.0/16,10.0.0.0/8,172.16.0.0/12 # 直连IP/网段
      - DIRECT_DOMAIN=localhost,fun,xyz,top                # 直连域名（主域匹配）
      - FORCE_DOMAIN=googleapis.cn,google.cn,gstatic.cn    # 强制走隧道，优先于全部直连规则

      # ===== TUN 细节参数（以下为默认值，按需调整）=====
      - TUN_STACK=gvisor                # gvisor（默认）/system/mixed
      - TUN_UDP_POLICY=direct           # 其余UDP：direct（默认）/block
      - TUN_FAKEIP=true                 # 被代理域名返回fake-ip，默认 true
      - TUN_DNS_PROXY=tcp://8.8.8.8     # 走隧道的DNS
      - TUN_DNS_CN=udp://223.5.5.5      # 国内域名直连解析DNS
      - TUN_ROUTE_EXCLUDE=              # 额外不进TUN的网段，逗号分隔；SSH服务器地址已自动排除
      - TUN_LOG_LEVEL=warn              # sing-box日志级别，排障时调 debug
      # - TUN_CONFIG=/app/logs/tun.json # 保留生成的配置便于排障（含明文凭据，用完删除）
      # - TUN_AUTO_REDIRECT=false       # Linux专属nftables加速，按需开启

      # ===== 日志与加密 =====
      - LOG_FORMAT=json                 # 日志格式：json（默认）/ text
      - LOG_LEVEL=info                  # 日志级别：debug/info（默认）/warn/error
      # - CIPHER_MASTER_KEY=            # DES3主密钥；自定义后 -encode 与服务必须用同一个值
    volumes:
      - ./logs:/app/logs
    # 并发调大后内存同步放宽：1024 并发约需 256MB（256 并发约 64MB）
    mem_limit: 512m
```

> 说明：
> - TUN 只能作用于 **Linux 宿主机**的宿主网络；Docker Desktop（Windows/macOS）的 host 网络指向虚拟机，无法接管宿主机流量，TUN 模式在这些平台不可用。
> - `network_mode: host` 下 `ports` 映射失效，SOCKS5/HTTP 端口直接监听宿主机；`BIND_ADDR=127.0.0.1` 时仅本机可用。
> - 镜像已按目标架构内置 sing-box（`/app/singbox`）：TUN 启动时直接调用，无需联网下载，也无需额外挂载；其它架构（如 armv7）的镜像不包含 sing-box，TUN 模式不可用。
> - 以 `user: "0"` 运行时，挂载目录 `./logs` 下新生成的日志与 `known_hosts` 属主为 root。
> - 验证：宿主机 `ip route | grep ssh-tun` 出现默认路由，`curl ifconfig.me` 返回服务器出口 IP。

- **UDP / DNS 行为**

| 流量 | 处理 |
|---|---|
| DNS 53 端口 | 劫持进内置 DNS：国内域名直连解析，其余经隧道 TCP DNS，防止 DNS 泄漏；内网域名（`.local`/`.lan` 等）走系统解析器 |
| UDP 443 (QUIC) | 非直连目标一律拒绝，QUIC 失败后浏览器立即回退 TCP 走隧道，避免 QUIC 直连绕过代理造成 IP 分裂；私网/`DIRECT_IP` 等直连目标仍按直连处理 |
| 其余 UDP | 默认直连放行（与未开启 TUN 时一致，不破坏 WebRTC/游戏）；`TUN_UDP_POLICY=block` 可全部拒绝 |
| 应用显式 DoH | 走 TCP 443 进隧道（分流不生效但不会断网），建议关闭 Firefox 等浏览器的 DoH |

- **排障**
  - 查看生成的配置：默认在系统临时目录生成随机文件名的 `ssh-tunnel-tun-*.json`，进程退出即删除；需要保留时用 `TUN_CONFIG` 指定固定路径
  - sing-box 输出按行透传到程序日志，调 `TUN_LOG_LEVEL=debug` 排查分流问题
  - 提示“未找到 sing-box（singbox）”：把对应架构的 sing-box 可执行文件改名为 `singbox` 放在程序同目录（镜像内已内置 `/app/singbox`），或安装到 `PATH`
  - sing-box 执行失败：日志会给出路径与原因，可检查文件是否具备执行权限、版本是否满足 >= 1.12
  - sing-box 异常退出时主进程记录错误并以退出码 1 退出，由 systemd `Restart=on-failure` / Docker `restart: unless-stopped` 恢复
  - 关闭程序即恢复系统网络：先发 SIGTERM 等待 sing-box 自行清理路由/网卡（5 秒超时后强制结束）

### 功能特性
- [X] 通过远程SSH代理建立隧道
- [X] 支持SOCKS5代理
- [X] 支持HTTP代理
- [X] 本机直接提供代理，不通过远程SSH代理（不配置 `-server` 即为本地代理模式）
- [X] 直连IP配置(支持IP和网段)，直连IP由本地直接访问，不经过远程SSH代理（`-direct-ip`，支持 CIDR 与点分掩码）
- [X] 直连域名配置(支持匹配主域名)，直连域名由本地直接访问，不经过远程SSH代理（`-direct-domain`）
- [X] 内置 geosite 数据(`dlc.dat`)，`-direct-cn` 一键中国域名全量直连(也可指定其它 geosite 列表)
- [X] 强制走隧道域名配置(`-force-domain`)，用于抵消直连规则的误伤（如 `geosite:cn` 收录 `googleapis.cn` 导致 Google Play 更新失效）
- [X] SOCKS5 支持 IPv6 目标地址(兼容 Android 双栈网络偏好解析 AAAA 的场景，如 Google Play 下载)，需隧道服务端具备 IPv6 出口
- [X] 周期性运行统计日志（每 5 分钟输出活跃/累计连接数与上下行字节），逐连接日志可用 `LOG_LEVEL=debug` 打开
- [X] 并发连接双维度上限（默认全局 256 / 单 IP 32，SOCKS5 与 HTTP 共享配额，可用 `MAX_CONNS` / `MAX_CONNS_PER_IP` 调整，`0` 表示不限制），超限直接关闭
- [X] 空闲连接回收（默认双向静默 30 分钟即关闭，可用 `IDLE_TIMEOUT` 调整，`0` 表示不回收），避免客户端休眠/掉线后的僵尸连接长期占用并发名额与 SSH 通道
- [X] SSH 会话重连指数退避（5s 起、60s 封顶，按槽位错开），服务器不可用时避免无效握手风暴与日志刷屏
- [X] HTTP 代理兼容 Java 生态客户端（Apache HttpClient / Jetty HttpClient / java.net.http.HttpClient）
- [X] 可选 TUN 全局接管（`TUN_MODE=1`）：托管 sing-box 子进程把系统全部流量导入本地 SOCKS5，内置 DNS 劫持、国内域名/私网直连分流与 QUIC 回退，未开启时行为与纯代理模式完全一致
- [X] 内置 sing-box（linux/amd64、linux/arm64）：镜像按目标架构只放入对应文件并统一命名 `singbox`，无需联网下载或手动安装

### 兼容性实测
- [X] v2rayN（Windows）
- [X] v2rayNG（Android）
- [X] Google Chrome
- [X] Google Play（Android）
- [X] Gitea（Docker环境变量）
- [X] Nexus3（系统内配置HTTP代理）
- [X] Linux（OpenEuler）
- [X] Windows 10/11
- [X] Android 16

### 加入群聊

<p>
<img src="docs/qrcode_qq.jpg" width="200">
</p>

> 点击链接加入群聊【AI开发新姿势】：https://qm.qq.com/q/ACxOjcQQqA
