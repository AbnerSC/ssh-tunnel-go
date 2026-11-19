#!/bin/sh
# =====================================================================
# ssh-tunnel 容器入口脚本
#
# 环境变量与命令行参数的装配逻辑（环境变量优先、命令行补充）已内置在二进制中，
# 因此脚本只做 exec 转发，保证 docker run 镜像 -D 6666 ... 的原生命令行用法继续可用。
#
# 支持的环境变量（均可选，未设置或为空则不生效）：
#   SOCKS_PORT      -> -D      本地 socks5 监听端口
#   SOCKS_USER      -> -suser  socks5/http 代理账号
#   SOCKS_PASSWORD  -> -spwd   socks5/http 代理密码
#   HTTP_PORT       -> -H      本地 http 代理监听端口
#   BIND_ADDR       -> -bind          代理端口的监听地址（默认 0.0.0.0）
#   ALLOW_UNAUTH_PUBLIC -> -allow-unauth-public 允许无认证代理对外监听（默认拒绝）
#   MAX_CONNS       -> -max-conns      代理并发连接上限（默认 256，0 不限制）
#   MAX_CONNS_PER_IP -> -max-conns-per-ip 单 IP 并发连接上限（默认 32，0 不限制）
#   IDLE_TIMEOUT    -> -idle-timeout    双向静默回收时长（默认 30m，0/off 不回收）
#   SSH_SERVER      -> -server 隧道服务器地址与账号，如 root@1.2.3.4
#   SSH_PORT        -> -p      服务器 SSH 端口
#   SSH_PASSWORD    -> -P      服务器 SSH 密码
#   SSH_POOL        -> -pool   SSH 连接池大小（默认 8）
#   SSH_KNOWN_HOSTS -> -known-hosts    服务端主机密钥记录文件
#   SSH_HOST_KEY    -> -host-key       固定服务端主机密钥指纹
#   DIRECT_IP       -> -direct-ip     直连 IP/网段，逗号或空格分隔
#   DIRECT_DOMAIN   -> -direct-domain 直连域名（主域匹配）
#   DIRECT_CN       -> -direct-cn     中国域名全量直连（geosite:cn）
#   FORCE_DOMAIN    -> -force-domain  强制走隧道的域名，优先于直连规则
#   LOG_FORMAT      -> json（默认）/ text
#   LOG_LEVEL       -> debug / info（默认）/ warn / error
#   CIPHER_MASTER_KEY -> （无对应参数）DES3 密文主密钥，-encode 与启动解密共用
#
# TUN 全局接管（TUN_MODE=1 开启；完整 Docker Compose 示例见 README）：
#   TUN_MODE           -> -tun             开启全局接管，托管 sing-box 导入系统全部流量
#   TUN_CONFIG         -> -tun-config      生成的配置输出路径；留空为临时文件（含明文凭据）
#   TUN_UDP_POLICY     -> -tun-udp-policy  其余 UDP：direct（默认）/ block
#   TUN_FAKEIP         -> -tun-fakeip      被代理域名返回 fake-ip（默认 true）
#   TUN_DNS_PROXY      -> -tun-dns-proxy   走隧道的 DNS（默认 tcp://8.8.8.8）
#   TUN_DNS_CN         -> -tun-dns-cn      国内域名直连解析 DNS（默认 udp://223.5.5.5）
#   TUN_ROUTE_EXCLUDE  -> -tun-route-exclude 额外不进 TUN 的网段（SSH 服务器地址自动排除）
#   TUN_STACK          -> -tun-stack       gvisor（默认）/ system / mixed
#   TUN_LOG_LEVEL      -> -tun-log-level   sing-box 日志级别（默认 warn）
#   TUN_AUTO_REDIRECT  -> -tun-auto-redirect  Linux 专属 nftables 加速（默认 false）
#
# TUN 容器运行条件（缺一不可，与 README 的 Docker Compose 示例一致）：
#   1. 以 root 运行：镜像默认非 root（uid 10001），docker run 需加 --user 0
#   2. NET_ADMIN 权限：--cap-add NET_ADMIN，用于创建 TUN 虚拟网卡
#   3. 挂载宿主机 TUN 设备：--device /dev/net/tun
#   4. 共享宿主机网络：--network host（TUN 只作用于宿主网络，host 下端口映射失效；
#      Docker Desktop 的 host 网络指向虚拟机，无法接管宿主机流量）
#   5. sing-box 已内置（构建时按目标架构只拷入 core/sing-box-<arch>，统一命名
#      /app/singbox）：TUN 启动时直接调用，无需联网下载或额外挂载；其它架构不含 sing-box
#   6. SOCKS_PORT 必填（TUN 唯一出站）；建议 BIND_ADDR=127.0.0.1、
#      MAX_CONNS_PER_IP=0 并调大 MAX_CONNS（并发与内存预算见 README）
# =====================================================================
set -e

exec /app/ssh-tunnel "$@"
