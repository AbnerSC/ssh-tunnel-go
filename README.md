# SSH隧道
通过SSH建立一个隧道

[![GitHub Stars](https://img.shields.io/github/stars/AbnerSC/ssh-tunnel-go?style=flat&label=Stars)](https://github.com/AbnerSC/ssh-tunnel-go/stargazers)
[![Docker Pulls](https://img.shields.io/docker/pulls/babyfly/ssh-tunnel?label=Docker%20Pulls)](https://hub.docker.com/r/babyfly/ssh-tunnel)

***GitHub***：[https://github.com/AbnerSC/ssh-tunnel-go.git](https://github.com/AbnerSC/ssh-tunnel-go.git)

### Go 1.27.3

### 依赖
- [domain-list-community](https://github.com/v2fly/domain-list-community.git) 20261015074526

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
| `JAVA_OPTS`      | -                | 覆盖镜像内置的 JVM 调优参数（可选）                                                            |

### 使用测试

1. 测试HTTP代理
```bash
# 未配置账号密码
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
- [X] SOCKS5 支持 IPv6 目标地址(兼容 Android 双栈网络偏好解析 AAAA 的场景，如 Google Play 下载)，需隧道服务端具备 IPv6 出口
