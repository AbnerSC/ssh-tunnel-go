---
name: update-singbox
description: 更新Sing-Box
---

# 用途
用于手动更新 Sing-Box 的执行文件

# 操作步骤
1. 从github下载文件后，覆盖本项目同名文件
2. 本项目文件存放位置：[sing-box-amd64](../../../core/sing-box-amd64) 和 [sing-box-arm64](../../../core/sing-box-arm64)
3. github下载地址：`https://github.com/SagerNet/sing-box/releases/latest`
4. 更新后检查，防止下载错误文件或者文件不完整
5. 下载时，网络使用操作系统代理
6. 下载 `Linux-amd64` 与 `Linux-arm64` 两个架构的发布包（tar.gz），分别解压出其中的 `sing-box` 可执行文件覆盖上面两个文件；只更新一个架构会导致该架构的镜像仍使用旧版本
7. 告诉我更新结果：是否更新，更新版本日期

# 下载失败时的镜像回退
1. 先直连并显式加短超时探测：`curl.exe -L -o NUL -s -S --max-time 30 -w "%{http_code} %{size_download}" <原始下载地址>`；直连可能报 `curl: (56) Recv failure: Connection was reset` 且耗时约 40 秒以上，必须带 `--max-time` 防止长时间阻塞
2. 直连失败后改用镜像前缀，把原始下载地址原样拼在镜像后：
   - 首选：`https://ghfast.top/<原始下载地址>`
   - 备选：`https://gh-proxy.com/<原始下载地址>`
   - 两者均曾探测返回 200 且大小正确；`ghproxy.net`、`ghp.ci` 曾失败或无法解析，镜像存活不稳定，需逐个探测而非写死
3. 探测返回 200 且 `size_download` 非 0 后再正式下载：`curl.exe -L --fail -s -S --max-time 180 -o tmp-sing-box <镜像地址>`
4. 覆盖前先比对：下载文件大小 + SHA256 与本地文件一致时说明已是最新，不要覆盖（避免无意义变更）；不一致才覆盖
5. 镜像下载的临时文件用完必须清理
6. 可用 GitHub API 确认最新 release 信息（版本号/发布日期/资产大小）：`https://github.com/SagerNet/sing-box/releases/latest`

# 注意
1. 更新 Sing-Box 操作需要用户主动发起，不能自动执行此操作
2. 两个二进制不再通过 `go:embed` 嵌入程序：Docker 构建时按目标架构只拷入对应文件并统一命名为 `/app/singbox`，更新后需重新构建/发布镜像才生效；非镜像部署需手动把对应文件改名为 `singbox` 放在程序同目录