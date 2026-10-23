# =====================================================================
# ssh-tunnel 多架构镜像构建文件（linux/amd64 & linux/arm64）
#
# 多阶段构建：
#   - 编译阶段固定在构建机原生架构（--platform=$BUILDPLATFORM），
#     通过 GOOS/GOARCH 交叉编译出目标架构的静态二进制，无需 QEMU 模拟
#   - 运行阶段基于 alpine（官方多架构镜像），仅拷贝静态二进制
#
# 与 Java 版镜像的兼容性：
#   - 环境变量 SOCKS_PORT / HTTP_PORT / SOCKS_USER / SOCKS_PASSWORD /
#     SSH_SERVER / SSH_PORT / SSH_PASSWORD / SSH_POOL / DIRECT_IP /
#     DIRECT_DOMAIN / DIRECT_CN 语义完全一致，docker-compose 无需修改
#   - 日志仍写入 /app/logs（按天滚动，保留 30 天 / 上限 1GB）
#   - 健康检查改用二进制内置的 -health 子命令，不依赖 bash 的 /dev/tcp
#
# 本地手动构建多架构镜像：
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -t ssh-tunnel:latest --push .
# 国内环境可注入 Go 模块代理加速依赖下载：
#   --build-arg GOPROXY=https://goproxy.cn,direct
# =====================================================================

# 运行时基础镜像：必须声明在第一个 FROM 之前（全局 ARG），否则后续 FROM 无法引用
ARG GO_IMAGE=golang:1.27-bookworm
ARG BASE_IMAGE=debian:bookworm-slim

# ---------- 阶段一：编译 ----------
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
WORKDIR /build

ARG GOPROXY=https://goproxy.cn,direct
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
ENV GOPROXY=${GOPROXY} \
    CGO_ENABLED=0

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

# 静态二进制不依赖 libc；ca-certificates 供直连目标时按系统证书校验（如有）
RUN apk add --no-cache ca-certificates

COPY --from=build /out/ssh-tunnel /app/ssh-tunnel

# 入口脚本仅做 exec 转发；环境变量 -> 参数 的转换已内置在二进制中
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# Windows 下检出可能带 CRLF，构建时统一去除，避免 shebang 解析失败
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh && \
    chmod +x /usr/local/bin/docker-entrypoint.sh

# 运行时环境变量（均可选，未设置或为空则不传对应参数；详见 README）：
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
#   LOG_FORMAT     -> json（默认）/ text（Java 版同构文本格式）
#   LOG_LEVEL      -> debug / info（默认）/ warn / error
#   JAVA_OPTS      -> Java 版遗留变量，Go 版接受但忽略
ENV SOCKS_PORT= \
    SOCKS_USER= \
    SOCKS_PASSWORD= \
    HTTP_PORT= \
    SSH_SERVER= \
    SSH_PORT= \
    SSH_PASSWORD= \
    SSH_POOL= \
    DIRECT_IP= \
    DIRECT_DOMAIN= \
    DIRECT_CN= \
    LOG_FORMAT= \
    LOG_LEVEL= \
    JAVA_OPTS=

ENTRYPOINT ["docker-entrypoint.sh"]

# 存活探测：内置子命令检查本地代理端口（优先 HTTP_PORT，未配则 SOCKS_PORT；
# 两者均未配置时恒健康），配合 restart 策略兜住进程异常退出/端口未就绪
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
    CMD ["/app/ssh-tunnel", "-health"]

# socks5 监听端口（README 示例 -D 6666），实际端口由启动参数/环境变量决定
EXPOSE 6666 6667
VOLUME ["/app/logs"]
