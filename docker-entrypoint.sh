#!/bin/sh
# =====================================================================
# ssh-tunnel 容器入口脚本
#
# 命令行补充」的装配逻辑内置到二进制中，因此脚本只做 exec 转发，
# 保证 docker run 镜像 -D 6666 ... 的原生命令行用法继续可用。
#
# 支持的环境变量（均可选，未设置或为空则不生效）：
#   SOCKS_PORT      -> -D      本地 socks5 监听端口
#   SOCKS_USER      -> -suser  socks5/http 代理账号
#   SOCKS_PASSWORD  -> -spwd   socks5/http 代理密码
#   HTTP_PORT       -> -H      本地 http 代理监听端口
#   BIND_ADDR       -> -bind          代理与 -L 端口的监听地址（默认 0.0.0.0）
#   ALLOW_UNAUTH_PUBLIC -> -allow-unauth-public 允许无认证代理对外监听（默认拒绝）
#   SSH_SERVER      -> -server 隧道服务器地址与账号，如 root@1.2.3.4
#   SSH_PORT        -> -p      服务器 SSH 端口
#   SSH_PASSWORD    -> -P      服务器 SSH 密码
#   SSH_POOL        -> -pool   SSH 连接池大小（默认 8）
#   SSH_KNOWN_HOSTS -> -known-hosts    服务端主机密钥记录文件
#   SSH_HOST_KEY    -> -host-key       固定服务端主机密钥指纹
#   DIRECT_IP       -> -direct-ip     直连 IP/网段，逗号或空格分隔
#   DIRECT_DOMAIN   -> -direct-domain 直连域名（主域匹配）
#   DIRECT_CN       -> -direct-cn     中国域名全量直连（geosite:cn）
#   LOG_FORMAT      -> json（默认）/ text
#   LOG_LEVEL       -> debug / info（默认）/ warn / error
#   JAVA_OPTS       -> Java 版遗留变量，Go 版忽略
# =====================================================================
set -e

exec /app/ssh-tunnel "$@"
