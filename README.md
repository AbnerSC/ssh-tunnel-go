# SSH 隧道（Go 版）

通过 SSH 建立隧道，在本地提供 SOCKS5 / HTTP 代理，并按直连规则把流量分流到本机直连或远程 SSH。

本仓库是 Java 版 ssh-tunnel 的 Go 重写，目标是**功能完全对齐 + 镜像无缝替换**：
既有 docker-compose 不需要修改任何一行（环境变量名、端口、日志目录、健康检查语义全部保持），
只需让容器重新拉取 `scdm/ssh-tunnel:latest` 即可切换。

## 功能特性

- [x] 通过远程 SSH 建立隧道，SOCKS5 与 HTTP 代理共用同一个连接池
- [x] SOCKS5 代理（RFC1928，无认证 / RFC1929 用户名密码认证，支持 IPv4 / IPv6 / 域名目标）
- [x] HTTP 代理（支持 `CONNECT` 隧道与普通 HTTP 转发，`Proxy-Authorization: Basic` 认证）
- [x] 本机直连模式（不配置 `SSH_SERVER` 时全部请求由本机转发）
- [x] 直连 IP（单 IP / CIDR / 点分掩码）、直连域名（主域匹配）、`geosite:cn` 全量直连
- [x] SSH 连接池（默认 8 条）、心跳保活、失败判死与自动重连
- [x] 端口转发：`-L` / `-s` 本地转发、`-R` 远程转发
- [x] 密码支持明文或最多 4 层 DES3 加密，内置 `-encode` 生成密文
- [x] 控制台 + 文件双输出日志，按天滚动，保留 30 天 / 上限 1GB
- [x] 结构化日志（默认 JSON），可切换为 Java 版同构文本格式
- [x] 内置健康检查子命令，无需 shell 的 `/dev/tcp`

## 快速开始（Docker）

与 Java 版**完全相同的** compose 可直接使用（仅示意，按实际环境调整）：

```yaml
services:
  ssh-tunnel:
    image: scdm/ssh-tunnel:latest
    container_name: ssh-tunnel
    restart: always
    hostname: linux
    environment:
      - TZ=Asia/Shanghai
      - SOCKS_PORT=11823
      - HTTP_PORT=11825
      - SOCKS_USER=user
      - SOCKS_PASSWORD=pwd123
      - SSH_SERVER=root@172.81.101.123
      - SSH_PORT=22
      - SSH_PASSWORD=croot!123
      - SSH_POOL=6
      - DIRECT_IP=192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,127.0.0.1,119.6.200.182
      - DIRECT_DOMAIN=localhost,mmxx.fun,05200809.xyz,openeuler.org
      - DIRECT_CN=true
    ports:
      - 11823:11823    # SOCKS5 端口
      - 11825:11825    # HTTP 端口
    volumes:
      - ./logs:/app/logs
```

切换步骤：

```bash
docker compose pull ssh-tunnel
docker compose up -d ssh-tunnel
docker compose logs -f ssh-tunnel          # 确认 "程序启动" / "socks5代理端口监听成功"
docker exec ssh-tunnel /app/ssh-tunnel -version
```

## 使用说明

### 命令行

```bash
# 远程 SSH 隧道
./ssh-tunnel -D 6666 -H 6667 -suser socks_user -spwd socks_pwd \
             -server root@1.2.3.4 -p 22 -P server_pwd

# 本机直连模式（不配置 -server）
./ssh-tunnel -D 6666 -H 6667
```

| 参数 | 说明 |
|------|------|
| `-D <port>` | 本地 SOCKS5 监听端口【可选】 |
| `-H <port>` | 本地 HTTP 代理监听端口（`CONNECT` 隧道 + 普通 HTTP 转发）【可选】 |
| `-suser <user>` | 代理账号，SOCKS5 与 HTTP 共用；与 `-spwd` 同时非空才启用认证【可选】 |
| `-spwd <pwd>` | 代理密码，支持 DES3 密文【可选】 |
| `-server [user@]host` | SSH 服务器；缺省账号 `root`，为空则为本机直连模式【可选】 |
| `-p <port>` | SSH 端口，默认 `22` |
| `-P <pwd>` | SSH 密码，支持 DES3 密文 |
| `-pool <n>` | SSH 连接池大小，默认 `8` |
| `-direct-ip <list>` | 直连 IP/网段，逗号或空格分隔，可重复传参 |
| `-direct-domain <list>` | 直连域名（主域匹配），逗号或空格分隔，可重复传参 |
| `-direct-cn [list]` | 中国域名全量直连，等价于 `-direct-cn cn`；也可写 `cn,private` 指定多个 geosite 列表 |
| `-L` / `-s <规则>` | 本地端口转发，可重复 |
| `-R <规则>` | 远程端口转发，可重复 |
| `-encode <明文>` | 输出 4 层 DES3 密文后退出 |
| `-health` | 探测本地代理端口，健康返回 `0`，否则返回 `1` |
| `-version` | 输出版本、commit、构建时间 |

> 参数解析沿用 Java 版语义：以 `-` 开头的 token 是参数名，其后一个 token 是取值；同名参数可重复累积。
> 环境变量优先于命令行同名参数，列表类参数（直连规则）两者合并。

### 端口转发

规则格式：`host:port-目标端口`（也兼容 `目标端口:host:port` 的三段冒号写法），
其中 `目标端口` 是监听端口，`host:port` 是通道对端地址。

```bash
# 本地监听 8080，经服务器访问 10.0.0.5:80
./ssh-tunnel ... -L 10.0.0.5:80-8080

# 服务器侧监听 127.0.0.1:9000，经通道回到本机访问 127.0.0.1:3000
./ssh-tunnel ... -R 127.0.0.1:3000-9000
```

- `-L` 与 `-s` 等价，均在本机 `0.0.0.0:<目标端口>` 监听，流量在连接池内轮询分发到各会话的 `direct-tcpip` 通道。
- `-R` 在服务器侧 `127.0.0.1:<目标端口>` 监听（仅回环），流量回到本机后直连 `host:port`。
- 远程转发只由「主会话」承担；主会话断开后由新会话重新选举并重建监听（监听失败自动重试 3 次）。

### 密码加密

与 Java 版使用同一套算法与密钥（DESede/CBC/PKCS5Padding + Base64，最多 4 层嵌套），
因此 Java 版已生成的密文可以直接在 Go 版使用：

```bash
./ssh-tunnel -encode 'my_password'
# 输出示例（4 层，直接填到 SSH_PASSWORD / -P）
```

运行时对 `SSH_PASSWORD`、`SOCKS_PASSWORD` 依次尝试解密，解密失败即按明文处理。

### 直连规则

配置了 `SSH_SERVER` 时，默认所有目标走 SSH 隧道；命中以下任一规则的目标由本机直接访问：

- `-direct-ip`：单 IP、CIDR（`10.0.0.0/8`）、点分掩码（`10.0.0.0/255.0.0.0`）、IPv6 字面量。
- `-direct-domain`：主域匹配，`example.com` 命中 `www.example.com` 与 `example.com` 本身。
- `-direct-cn`：加载内置 `dlc.dat`（[domain-list-community](https://github.com/v2fly/domain-list-community)）中的 `geosite:cn` 列表，
  共 6624 条规则（domain / full / regexp），并按其匹配语义生效。
  显式设置为 `false`/`0`/`no`/`off` 表示关闭，不再加载任何 geosite 列表。

IP 字面量目标只参与 IP 规则匹配，不做反向域名匹配（与 Java 版一致）。

### 环境变量

| 环境变量 | 对应参数 | 说明 |
|----------|----------|------|
| `SOCKS_PORT` | `-D` | 本地 SOCKS5 监听端口 |
| `HTTP_PORT` | `-H` | 本地 HTTP 代理监听端口 |
| `SOCKS_USER` | `-suser` | 代理账号（可选） |
| `SOCKS_PASSWORD` | `-spwd` | 代理密码（可选，支持 DES3 密文） |
| `SSH_SERVER` | `-server` | SSH 服务器，如 `root@1.2.3.4`（可选，为空则本机直连模式） |
| `SSH_PORT` | `-p` | SSH 端口，默认 `22` |
| `SSH_PASSWORD` | `-P` | SSH 密码（支持 DES3 密文） |
| `SSH_POOL` | `-pool` | SSH 连接池大小，默认 `8` |
| `DIRECT_IP` | `-direct-ip` | 直连 IP/网段，逗号或空格分隔 |
| `DIRECT_DOMAIN` | `-direct-domain` | 直连域名，逗号或空格分隔 |
| `DIRECT_CN` | `-direct-cn` | `true`/`1`/`yes`/`on` 启用 `cn` 列表，也可写 `cn,private`；`false` 显式关闭 |
| `LOG_FORMAT` | - | `json`（默认）或 `text`（Java 版同构文本格式） |
| `LOG_LEVEL` | - | `debug` / `info`（默认） / `warn` / `error` |
| `JAVA_OPTS` | - | Java 版遗留变量，Go 版接受但忽略（compose 无需删除） |
| `TZ` | - | 时区；二进制已内嵌 `time/tzdata`，alpine 基础镜像同样生效 |

### 日志

- 控制台与文件同时输出，先写文件再写控制台（互不影响）；文件写入 `/app/logs/ssh-tunnel.log`（容器内路径，建议挂载出来）。
- 按天滚动：跨天时归档为 `/app/logs/ssh-tunnel.YYYY-MM-DD.log`，保留 30 天，归档总量上限 1GB（超出优先删最旧）。
- 默认 JSON，每行一条：

```json
{"time":"2026-10-23T12:00:00.123+08:00","level":"INFO","msg":"socks5代理端口监听成功","component":"main","port":11823}
```

- `LOG_FORMAT=text` 时输出 Java logback 同构文本，便于复用既有日志解析：

```
2026-10-23 12:00:00.123 [main] INFO  org.open.scdm.common.ssh.Logf - socks5代理端口监听成功 port=11823
```

## 本地开发

```bash
# 构建（Windows 产物为 ssh-tunnel.exe）
go build -o ssh-tunnel ./cmd/ssh-tunnel

# 全量检查
gofmt -l .
go vet ./...
go test ./... -race -count=1

# 交叉编译到 Linux
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o ssh-tunnel ./cmd/ssh-tunnel
```

### 目录结构

```
cmd/ssh-tunnel/     入口：一次性命令（-version/-health/-encode）、装配与信号处理
internal/config/    参数与环境变量装配、DES3、端口转发规则解析
internal/console/   缺失配置的控制台补参（非终端环境不阻塞）
internal/direct/    直连规则（IP/CIDR/域名）与内置 geosite dlc.dat 解析
internal/logging/   slog 双格式输出与按天滚动文件
internal/proxy/     SOCKS5、HTTP 代理与双向转发
internal/sshpool/   SSH 连接池、心跳重连、-L/-R 端口转发
```

### 测试

测试覆盖各模块，并在进程内启动真实 SSH 服务器验证隧道、端口转发与断线重连：

```bash
go test ./... -race -count=1
```

| 包 | 覆盖内容 |
|----|----------|
| `internal/config` | 参数解析、生产 compose env 装配、DES3 与 Java 黄金向量对齐、转发规则解析 |
| `internal/direct` | IP/CIDR/点分掩码/域名主域匹配、非法值容错、geosite 规则数量与匹配 |
| `internal/logging` | 跨天归档、30 天清理、1GB 上限、文本格式、级别过滤 |
| `internal/proxy` | SOCKS5 握手/认证/域名应答、HTTP CONNECT/407 重试/请求头改写/64KB 上限 |
| `internal/sshpool` | 隧道拨号、本地/远程转发、认证失败、服务端重启后自动重连 |
| `cmd/ssh-tunnel` | 健康检查、一次性命令、真实启动后的 SOCKS5 与 HTTP 端到端代理 |

### Docker 镜像构建

多阶段构建：`golang:1.27-alpine` 交叉编译静态二进制，运行阶段为 `alpine:3.22`。

```bash
# 单架构
docker build -t ssh-tunnel:dev .

# 多架构
docker buildx build --platform linux/amd64,linux/arm64 -t ssh-tunnel:dev .

# 国内环境加速 Go 依赖
docker build --build-arg GOPROXY=https://goproxy.cn,direct -t ssh-tunnel:dev .
```

注入版本信息：

```bash
docker build \
  --build-arg VERSION=1.2.3 \
  --build-arg COMMIT=$(git rev-parse --short=12 HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t ssh-tunnel:1.2.3 .
```

### CI

| 工作流 | 触发 | 目标 |
|--------|------|------|
| `.gitea/workflows/docker-image.yml` | push `main` / `release-v*` tag / 手动 | 推送 `scdm/ssh-tunnel` 到自建 Nexus（`linux/amd64`） |
| `.github/workflows/docker-image.yml` | tag / PR / 手动 | 先 `gofmt`+`vet`+`test` 门禁，再推送多架构镜像到 Docker Hub（`babyfly/ssh-tunnel`） |

`release-vX.Y.Z` tag 会同时产出 `X.Y.Z` 与 `latest` 两个标签；手动选择分支触发时仅推送 `latest`。
Gitea 侧需要配置 `NEXUS_REGISTRY_DOCKER` / `NEXUS_USERNAME` / `NEXUS_PASSWORD`，
GitHub 侧需要配置 `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN`。

## 与 Java 版的差异

功能与外部行为保持一致，差异仅在实现与运行开销：

| 维度 | Java 版 | Go 版 |
|------|---------|-------|
| 运行时 | JDK 25 + Vert.x + MINA SSHD | 单个静态二进制，无 JVM |
| 内存 | 需按堆 + 元空间/线程栈预留（`mem_limit` 常需 1g） | 常驻内存低，`mem_limit: 512m` 足够 |
| 并发模型 | 事件循环 + 虚拟线程 | goroutine + 阻塞 IO |
| 日志格式 | logback 文本 | 默认 JSON，`LOG_FORMAT=text` 可切回文本 |
| 健康检查 | 依赖 `bash` 的 `/dev/tcp` | 二进制内置 `-health` |
| 基础镜像 | `eclipse-temurin:25-jdk-noble` | `alpine:3.22` |
| `JAVA_OPTS` | 调整 JVM 参数 | 接受但忽略 |

行为上刻意保持一致的细节：

- 环境变量名、默认值、优先级；`user@host` 缺省账号 `root`
- SOCKS5 成功/失败应答回显请求地址（域名类型含长度字节），不支持的 `CMD` 直接关闭连接
- HTTP 代理 `CONNECT` 返回 `200 Connection established`，普通转发改写请求行、剔除 `proxy-authorization`/`proxy-connection`/`connection` 并追加 `Connection: close`
- HTTP 407 认证失败后可在同一连接重试；请求头上限 64KB，首字节超时 5s、整体接收超时 15s
- SSH 连接池默认 8、15s 心跳、连续 3 次失败判死、5s 退避重连（按槽位错峰）；通道拨号失败自动换一个会话重试，`-R` 由主会话承担且仅绑定回环
- 建连超时 3s（代理直连）/ 10s（SSH 认证与通道）
- 密码 DES3 密钥、IV、层数与密文格式，Java 版密文可直接使用

## 迁移检查清单

- [ ] 镜像仓库中的 `scdm/ssh-tunnel:latest` 已更新为 Go 版（`docker exec ssh-tunnel /app/ssh-tunnel -version` 可确认）
- [ ] 日志目录仍挂载到 `/app/logs`，历史日志与归档策略不受影响
- [ ] 代理端口、账号密码、直连规则等环境变量无需改动
- [ ] 依赖 `JAVA_OPTS` 的 compose 可保留该变量（Go 版忽略），无需删除
- [ ] `mem_limit` 可从 1g 下调到 512m（按实际连接数评估）
- [ ] 若使用 `LOG_FORMAT=text`，既有日志解析规则可继续工作；默认 JSON 需相应调整采集规则
