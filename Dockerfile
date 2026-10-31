# =====================================================================
# ssh-tunnel 多架构镜像构建文件（linux/amd64 & linux/arm64）
#
# 多阶段构建：
#   - 编译阶段固定在构建机原生架构（--platform=$BUILDPLATFORM），
#     通过 GOOS/GOARCH 交叉编译出目标架构的静态二进制，编译阶段无需 QEMU 模拟
#   - 运行阶段基于 debian bookworm-slim（官方多架构镜像），拷贝静态二进制并安装
#     ca-certificates；该阶段的 apt-get 以目标架构执行，跨架构构建需要 QEMU
#     （CI 已通过 setup-qemu 提供）
#
# 与 Java 版镜像的兼容性：
#   - 环境变量 SOCKS_PORT / HTTP_PORT / SOCKS_USER / SOCKS_PASSWORD /
#     SSH_SERVER / SSH_PORT / SSH_PASSWORD / SSH_POOL / DIRECT_IP /
#     DIRECT_DOMAIN / DIRECT_CN 语义完全一致，docker-compose 无需修改
#   - 日志仍写入 /app/logs（按天滚动，保留 30 天 / 上限 1GB）
#   - 健康检查改用二进制内置的 -health 子命令，不依赖 bash 的 /dev/tcp
#
# 安全基线（以非 root 运行）：
#   - 运行阶段只装 ca-certificates，不装 curl/调试工具，减小攻击面
#   - 使用 uid/gid 10001 的非特权用户，/app 与其下 known_hosts、logs 均归其所有
#   - 日志目录 0750、日志文件 0640，不对其他用户开放
#   - 若需监听 1024 以下端口，请用 --cap-add=NET_BIND_SERVICE 或改用高位端口
#
# 本地手动构建多架构镜像：
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -t ssh-tunnel:latest --push .
# 模块代理默认不注入（GitHub Actions / 本地直连 Go 官方 proxy.golang.org）；
# 国内环境构建由 Gitea Actions 注入内部 Go 代理加速依赖下载；
# 手动构建同样可选注入公共代理：
#   --build-arg GOPROXY=https://goproxy.cn,direct
# 同样可选的 apt 镜像源（加速运行阶段 ca-certificates 安装）：
#   --build-arg APT_MIRROR=repo.huaweicloud.com
# =====================================================================

# 全局 ARG：构建与运行基础镜像都必须在第一个 FROM 之前声明，否则后续 FROM 无法引用
ARG GO_IMAGE=golang:1.27-bookworm
ARG BASE_IMAGE=debian:bookworm-slim
# 可选：Debian apt 镜像源（仅运行阶段执行 apt-get 安装时生效）。
# 默认不注入，保持官方 deb.debian.org；国内环境由 Gitea Actions 经 build-arg
# 注入公共镜像源加速，为空时运行阶段跳过替换
ARG APT_MIRROR=

# ---------- 阶段一：编译 ----------
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
WORKDIR /build

# 可选：模块代理默认不注入，保持 Go 官方默认行为（proxy.golang.org + direct），
# 供 GitHub Actions / 本地直接构建；国内环境由 Gitea Actions 通过 build-arg 注入
ARG GOPROXY
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
ENV CGO_ENABLED=0
# 仅在显式传入时才写入 go env（持久化到后续构建步骤），未传时完全不改动默认代理
RUN if [ -n "$GOPROXY" ]; then go env -w GOPROXY="$GOPROXY"; fi

# 先拷依赖清单预取模块，源码变更时可复用 Docker 层缓存
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# TARGETOS/TARGETARCH 由 buildkit 按 --platform 自动注入
ARG TARGETOS
ARG TARGETARCH
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
        -trimpath -buildvcs=false \
        -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildAt=${BUILD_DATE}" \
        -o /out/ssh-tunnel ./cmd/ssh-tunnel

# ---------- 阶段二：运行时镜像 ----------
FROM ${BASE_IMAGE}
WORKDIR /app

ARG APT_MIRROR

# 静态二进制不依赖 libc；ca-certificates 供直连目标时按系统证书校验（如有）
# 不安装 curl 等调试工具：镜像内没有可以从外部触发的下载/命令执行工具链
# 动态替换镜像源（兼容 DEB822 格式与旧版 sources.list 格式；APT_MIRROR 为空则保持官方源）
RUN if [ -n "${APT_MIRROR}" ]; then \
        sed -i "s|deb.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list.d/debian.sources 2>/dev/null || true; \
        sed -i "s|security.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list.d/debian.sources 2>/dev/null || true; \
        sed -i "s|deb.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list 2>/dev/null || true; \
    fi && \
    apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /out/ssh-tunnel /app/ssh-tunnel

# 非 root 运行：进程被攻破后拿到的只是普通用户权限，无法直接改二进制/读宿主目录
ARG APP_UID=10001
ARG APP_GID=10001
RUN groupadd -g ${APP_GID} app && \
    useradd -u ${APP_UID} -g ${APP_GID} -M -d /app -s /usr/sbin/nologin app && \
    mkdir -p /app/logs && \
    touch /app/known_hosts && \
    chown -R app:app /app && \
    chmod 0750 /app/logs && \
    chmod 0600 /app/known_hosts

# 入口脚本仅做 exec 转发；环境变量 -> 参数 的转换已内置在二进制中
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# Windows 下检出可能带 CRLF，构建时统一去除，避免 shebang 解析失败
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh && \
    chmod +x /usr/local/bin/docker-entrypoint.sh

# 运行时环境变量（均可选，未设置或为空则不生效；详见 README）：
#   SOCKS_PORT     -> -D      本地 socks5 监听端口
#   SOCKS_USER     -> -suser  socks5/http 代理账号
#   SOCKS_PASSWORD -> -spwd   socks5/http 代理密码
#   HTTP_PORT      -> -H      本地 http 代理监听端口
#   SSH_SERVER     -> -server 隧道服务器地址与账号，如 root@1.2.3.4
#   SSH_PORT       -> -p      服务器 SSH 端口
#   SSH_PASSWORD   -> -P      服务器 SSH 密码
#   SSH_POOL       -> -pool   SSH 连接池大小（默认 8）
#   DIRECT_IP      -> -direct-ip     直连 IP/网段
#   DIRECT_DOMAIN  -> -direct-domain 直连域名（主域匹配）
#   DIRECT_CN      -> -direct-cn     中国域名全量直连（geosite:cn）
#   FORCE_DOMAIN   -> -force-domain   强制走隧道的域名，优先于直连规则
#   LOG_FORMAT     -> json（默认）/ text（Java 版同构文本格式）
#   LOG_LEVEL      -> debug / info（默认）/ warn / error
#   BIND_ADDR      -> -bind          代理与 -L 端口的监听地址（默认 0.0.0.0）
#   ALLOW_UNAUTH_PUBLIC -> -allow-unauth-public 允许无认证代理对外监听（默认拒绝）
#   ALLOW_PUBLIC_FORWARD -> -allow-public-forward 允许无认证的 -L 转发端口对外监听（默认拒绝）
#   MAX_CONNS      -> -max-conns      代理并发连接上限（默认 256，0 表示不限制）
#   MAX_CONNS_PER_IP -> -max-conns-per-ip 单来源 IP 并发连接上限（默认 32，0 表示不限制）
#   SSH_KNOWN_HOSTS -> -known-hosts  服务端主机密钥记录文件（默认 /app/known_hosts）
#   SSH_HOST_KEY    -> -host-key     固定服务端主机密钥指纹（SHA256:...，可逗号分隔多个）
#   JAVA_OPTS      -> Java 版遗留变量，Go 版接受但忽略
ENV SOCKS_PORT= \
    SOCKS_USER= \
    SOCKS_PASSWORD= \
    HTTP_PORT= \
    BIND_ADDR= \
    ALLOW_UNAUTH_PUBLIC= \
    ALLOW_PUBLIC_FORWARD= \
    MAX_CONNS= \
    MAX_CONNS_PER_IP= \
    SSH_SERVER= \
    SSH_PORT= \
    SSH_PASSWORD= \
    SSH_POOL= \
    SSH_KNOWN_HOSTS= \
    SSH_HOST_KEY= \
    DIRECT_IP= \
    DIRECT_DOMAIN= \
    DIRECT_CN= \
    FORCE_DOMAIN= \
    LOG_FORMAT= \
    LOG_LEVEL= \
    JAVA_OPTS=

USER app

ENTRYPOINT ["docker-entrypoint.sh"]

# 存活探测：内置子命令检查本地代理端口（优先 HTTP_PORT，未配则 SOCKS_PORT；
# 两者均未配置时恒健康），配合 restart 策略兜住进程异常退出/端口未就绪
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
    CMD ["/app/ssh-tunnel", "-health"]

# socks5 监听端口（README 示例 -D 6666），实际端口由启动参数/环境变量决定
EXPOSE 6666 6667
VOLUME ["/app/logs"]
