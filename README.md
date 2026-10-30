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
    hostname: linux
    restart: unless-stopped
    environment:
      - TZ=Asia/Shanghai
      - SOCKS_PORT=6666
      - HTTP_PORT=6667
      - SOCKS_USER=socks_user
      - SOCKS_PASSWORD=socks_pwd
      - SSH_SERVER=root@1.2.3.4
      - SSH_PORT=2
      - SSH_PASSWORD=server_pwd
      - SSH_POOL=6
      - DIRECT_IP=192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,127.0.0.1/8
      - DIRECT_DOMAIN=localhost,xxxx.fun,xxxx.xyz
      - FORCE_DOMAIN=googleapis.cn,google.cn,gstatic.cn
      - DIRECT_CN=true
    ports:
      - 16666:6666
      - 16667:6667
    volumes:
      - ./logs:/app/logs
    mem_limit: 128m
```

- 环境变量说明：

| 环境变量         | 对应参数         | 说明                                                                                           |
|------------------|------------------|------------------------------------------------------------------------------------------------|
| `SOCKS_PORT`     | `-D`             | 本地socks5监听端口                                                                             |
| `HTTP_PORT`      | `-H`             | 本地http代理监听端口                                                                           |
| `SOCKS_USER`     | `-suser`         | 代理账号，socks5 与 http 代理共用（可选）                                                      |
| `SOCKS_PASSWORD` | `-spwd`          | 代理密码，socks5 与 http 代理共用（可选）                                                      |
| `SSH_SERVER`     | `-server`        | 隧道服务器地址与账号，如 `root@1.2.3.4`（可选）当为空时，默认本机直接提供代理                  |
| `SSH_PORT`       | `-p`             | 服务器SSH端口（可选）,跟随`SSH_SERVER`一起配置                                                 |
| `SSH_PASSWORD`   | `-P`             | 服务器SSH密码（可选）,跟随`SSH_SERVER`一起配置                                                 |
| `SSH_POOL`       | `-pool`          | SSH 连接池大小（可选），建议不配置，默认配置已最优                                             |
| `DIRECT_IP`      | `-direct-ip`     | 直连IP/网段（逗号或空格分隔多个值，可选）                                                      |
| `DIRECT_DOMAIN`  | `-direct-domain` | 直连域名，匹配主域名（逗号或空格分隔，可选）                                                   |
| `DIRECT_CN`      | `-direct-cn`     | 中国域名全量直连，取值 `true` 启用默认 `cn` 列表，也可直接写 geosite 名(如 `cn,private`，可选) |
| `FORCE_DOMAIN`   | `-force-domain`  | 强制走 SSH 隧道的域名（主域匹配），优先级高于全部直连规则（可选）                             |
| `BIND_ADDR`      | `-bind`          | 代理与 `-L` 转发端口的监听地址，默认 `0.0.0.0`；设 `127.0.0.1` 则仅本机可用（可选）            |
| `ALLOW_UNAUTH_PUBLIC` | `-allow-unauth-public` | 允许在非回环地址上提供**无认证**代理，默认 `false`（启动时报错）                        |
| `SSH_KNOWN_HOSTS` | `-known-hosts`  | 服务端主机密钥记录文件，默认工作目录下的 `known_hosts`（容器内为 `/app/known_hosts`）         |
| `SSH_HOST_KEY`   | `-host-key`      | 固定服务端主机密钥指纹（`SHA256:...`），可重复传参或逗号分隔多个；设置后只接受匹配的指纹         |

### 安全基线（重要）

代理端口一旦暴露在网络上，就是一个能访问服务器侧内网的入口，部署前请确认以下几项：

1. **必须配置代理认证**。`SOCKS_USER` 与 `SOCKS_PASSWORD` 需要**同时**配置；只配其中一个会直接启动失败（旧版会静默降级成无认证代理）。
2. **无认证代理默认不允许对外监听**。未配认证且 `BIND_ADDR` 不是回环地址时进程会拒绝启动，并提示三种处理方式：
   - 配置 `SOCKS_USER` + `SOCKS_PASSWORD`；
   - 设 `BIND_ADDR=127.0.0.1`（仅本机/同机容器使用）；
   - 确认有网络隔离后显式设 `ALLOW_UNAUTH_PUBLIC=true`。
3. **认证失败会限速封禁**。同一来源 IP 1 分钟内失败 10 次即封禁 5 分钟，并把连接压到不可爆破的速率；成功认证会清零计数。
4. **SSH 主机密钥默认首次信任（TOFU）**。首次连接会把服务端指纹写入 `SSH_KNOWN_HOSTS`，之后指纹变化会拒绝连接并报“主机密钥已变更”；生产环境建议直接用 `SSH_HOST_KEY` 固定指纹，避免首次连接被中间人冒领：
   ```bash
   ssh-keyscan -p 22 1.2.3.4 | ssh-keygen -lf -   # 取 SHA256 指纹
   ```
5. **HTTPS 请用 CONNECT 隧道**。普通 HTTP 转发会改写 `Host`、剔除逐跳头与 `X-Forwarded-For`/`X-Real-IP` 等可伪造来源的头，并拒绝 `Transfer-Encoding` 与 `Content-Length` 共存的请求；HTTPS 走 `CONNECT` 全程加密透传。
6. **日志已清洗**。文本模式下字段值中的换行/控制字符会被转义，无法通过用户名等输入伪造整行日志；日志文件权限为 `0640`。
7. **容器以非 root 运行**（uid 10001），只装 `ca-certificates`；如需监听 1024 以下端口请用 `--cap-add=NET_BIND_SERVICE` 或改用高位端口。
8. **建议再叠一层运行时约束**。镜像本身已用非 root，但 Docker 默认仍允许提权到 setuid 程序，建议启动时补上下面三个参数（实测镜像在非 root 下 `CapEff` 已为 0，再加这些参数可进一步封死提权与落盘）：
   ```bash
   docker run -d --name ssh-tunnel \
     --security-opt no-new-privileges \
     --cap-drop ALL \
     --read-only --tmpfs /tmp \
     -v ssh-tunnel-logs:/app/logs \
     -p 127.0.0.1:6666:6666 -p 127.0.0.1:6667:6667 \
     -e SOCKS_PORT=6666 -e HTTP_PORT=6667 \
     -e SOCKS_USER=user -e SOCKS_PASSWORD=pwd \
     -e SSH_SERVER=root@1.2.3.4 -e SSH_PASSWORD=pwd \
     ssh-tunnel:latest
   ```
   注意 `--read-only` 时 `/app/known_hosts` 需改为挂载到可写卷（或改用 `SSH_HOST_KEY` 固定指纹，不再落盘），端口发布也请绑定回环地址。

### 使用测试

1. 测试HTTP代理
```bash
# 未配置账号密码（仅限 BIND_ADDR=127.0.0.1 或 ALLOW_UNAUTH_PUBLIC=true）
curl -x http://127.0.0.1:6667 https://www.google.com

# 已配置账号密码
curl -x http://socks_user:socks_pwd@127.0.0.1:6667 https://www.google.com
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
- [X] SSH 会话重连指数退避（5s 起、60s 封顶，按槽位错开），服务器不可用时避免无效握手风暴与日志刷屏
