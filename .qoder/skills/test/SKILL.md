---
name: test
description: 开发环境功能实测
---

# 已知
1. 开发测试服务器
```
IP：172.17.1.229
SSH端口：22
账号：root
密码：jIIGLcV0EmJFi0
系统盘：60GB SSD
数据盘：200GB SSD
```

2. 远程SSH服务器
```
IP：172.81.101.78
SSH端口：32192
账号：root
密码：D2ilj@Etfo$94m
```

3. 开发环境拉取镜像命令 `docker pull scdm/ssh-tunnel:latest`

# 要求
1. 帮我到开发测试服务器做完整功能测试
2. 关闭TUN，测试Socks和Http代理，包括直连模式和代理模式
3. 开启TUN，测试本机访问Google、百度，测试Socks和Http代理，包括直连模式和代理模式
4. 发现问题直接修复，直到问题全部解决
5. 测试内容不限于我提到的，一定要全方位测试所有正常和异常情况，全方位保障系统功能、性能、安全
6. 告诉我最终结果，我不看问题及修复情况，我只看功能、性能、安全测试方法及结论

## 测试网站
1. 百度：https://www.baidu.com/
2. 腾讯：https://www.qq.com/
3. 局域网：https://onenav.pi.mmxx.fun/
4. Google：https://www.google.com/
5. GitHub：https://github.com/
6. Docker：https://hub.docker.com/
7. Youtube：https://www.youtube.com/
8. 路由器：http://172.17.1.1
> 根据测试需要，还可以继续测试其他网站，需要覆盖：中国、美国、台湾、香港、局域网、本机回环等等各种网络

# 特别说明
1. 只有用户主动要求到服务器测试时才执行，不允许自动执行