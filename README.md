# SSH隧道
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
      - SOCKS_PORT=6666
      - HTTP_PORT=6667
      - SOCKS_USER=socks_user     # 代理账号
      - SOCKS_PASSWORD=socks_pwd  # 代理密码
      - SSH_SERVER=root@1.2.3.4   # 服务器地址与账号
      - SSH_PORT=22               # 服务器SSH端口
      - SSH_PASSWORD=server_pwd   # 服务器SSH密码
      - DIRECT_IP=192.168.0.0/16,10.0.0.0/8,172.16.0.0/12
      - DIRECT_DOMAIN=localhost,xxxx.fun # 直连域名
      - DIRECT_CN=true
      - FORCE_DOMAIN=googleapis.cn,google.cn,gstatic.cn # 强制代理域名
      - SSH_KNOWN_HOSTS=/app/logs/known_hosts
    ports:
      - 16666:6666
      - 16667:6667
    volumes:
      - ./logs:/app/logs
    mem_limit: 128m
```

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
| `SSH_KNOWN_HOSTS`      | 服务端主机密钥记录文件，默认工作目录下的 `known_hosts`（容器内为 `/app/logs/known_hosts`）（可选）                                                                                                      |
| `SSH_HOST_KEY`         | 固定服务端主机密钥指纹（`SHA256:...`），可重复传参或逗号分隔多个；设置后只接受匹配的指纹 （可选）                                                                                                  |
| `CIPHER_MASTER_KEY`    | DES3 密文主密钥，`-encode` 加密与启动解密共用；未设置时回退内置默认密钥。高安全部署建议通过 docker secrets / K8s Secret 注入自定义值，让源码里的默认密钥不参与加解密 |

### 部署须知（安全）

1. **代理认证必须成对配置**。`SOCKS_USER` 与 `SOCKS_PASSWORD` 需要**同时**配置，只配其中一个会直接启动失败。
2. **无认证不允许对外监听**。未配认证且 `BIND_ADDR` 不是回环地址时进程拒绝启动，三选一：配齐认证；设 `BIND_ADDR=127.0.0.1`（仅本机/同机容器）；确认网络隔离后显式设 `ALLOW_UNAUTH_PUBLIC=true`。
3. **SSH 主机密钥默认首次信任（TOFU）**。首次连接会把服务端指纹写入 `SSH_KNOWN_HOSTS`（容器内默认为 `/app/logs/known_hosts`，建议改到已挂载的可写目录里持久化，否则每次重建都要重新信任），之后指纹变化会拒绝连接并报“主机密钥已变更”；生产环境建议用 `SSH_HOST_KEY` 固定指纹：
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

### 功能特性
- [X] 通过远程SSH代理建立隧道
- [X] 支持SOCKS5代理
- [X] 支持HTTP代理
- [X] 本机直接提供代理，不通过远程SSH代理（不配置 `-server` 即为本地代理模式）
- [X] 增加直连IP配置(支持IP和网段)，直连IP由本地直接访问，不经过远程SSH代理（`-direct-ip`，支持 CIDR 与点分掩码）
- [X] 增加直连域名配置(支持匹配主域名)，直连域名由本地直接访问，不经过远程SSH代理（`-direct-domain`）
- [X] 内置 geosite 数据(`dlc.dat`)，`-direct-cn` 一键中国域名全量直连(也可指定其它 geosite 列表)
- [X] 强制走隧道域名配置(`-force-domain`)，用于抵消直连规则的误伤（如 `geosite:cn` 收录 `googleapis.cn` 导致 Google Play 更新失效）
- [X] SOCKS5 支持 IPv6 目标地址(兼容 Android 双栈网络偏好解析 AAAA 的场景，如 Google Play 下载)，需隧道服务端具备 IPv6 出口
- [X] 周期性运行统计日志（每 5 分钟输出活跃/累计连接数与上下行字节），逐连接日志可用 `LOG_LEVEL=debug` 打开
- [X] 并发连接双维度上限（默认全局 256 / 单 IP 32，SOCKS5 与 HTTP 共享配额，可用 `MAX_CONNS` / `MAX_CONNS_PER_IP` 调整，`0` 表示不限制），超限直接关闭
- [X] SSH 会话重连指数退避（5s 起、60s 封顶，按槽位错开），服务器不可用时避免无效握手风暴与日志刷屏
- [X] HTTP 代理兼容 Java 生态客户端（Apache HttpClient / Jetty HttpClient / java.net.http.HttpClient）

### 兼容性实测
- [X] v2rayN
- [X] v2rayNG
- [X] Google Play
- [X] Gitea
- [X] Linux（OpenEuler）
- [X] Nexus3
