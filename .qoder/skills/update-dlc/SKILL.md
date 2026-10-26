---
name: update-dlc
description: 更新域名列表
---

# 用途
用于手动更新域名列表文件`dlc.dat`

# 操作步骤
1. 从github下载`dlc.dat`文件后，覆盖本项目同名文件
2. 本项目文件存放位置：[dlc.dat](../../../internal/direct/dlc.dat)
3. github下载地址：https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
4. 更新后检查，防止下载错误文件或者文件不完整
5. 下载时，网络使用操作系统代理
6. 告诉我更新结果：是否更新，更新版本日期

# 下载失败时的镜像回退
1. 先直连并显式加短超时探测：`curl.exe -L -o NUL -s -S --max-time 30 -w "%{http_code} %{size_download}" <原始下载地址>`；直连可能报 `curl: (56) Recv failure: Connection was reset` 且耗时约 40 秒以上，必须带 `--max-time` 防止长时间阻塞
2. 直连失败后改用镜像前缀，把原始下载地址原样拼在镜像后：
   - 首选：`https://ghfast.top/<原始下载地址>`
   - 备选：`https://gh-proxy.com/<原始下载地址>`
   - 两者均曾探测返回 200 且大小正确；`ghproxy.net`、`ghp.ci` 曾失败或无法解析，镜像存活不稳定，需逐个探测而非写死
3. 探测返回 200 且 `size_download` 非 0 后再正式下载：`curl.exe -L --fail -s -S --max-time 180 -o dlc_tmp.dat <镜像地址>`
4. 覆盖前先比对：下载文件大小 + SHA256 与本地 [dlc.dat](../../../internal/direct/dlc.dat) 一致时说明已是最新，不要覆盖（避免无意义变更）；不一致才覆盖
5. 镜像下载的临时文件（如 `dlc_tmp.dat`）用完必须清理
6. 可用 GitHub API 确认最新 release 信息（版本号/发布日期/资产大小）：`https://api.github.com/repos/v2fly/domain-list-community/releases/latest`

# 注意
1. 更新域名列表操作需要用户主动发起，不能自动执行此操作