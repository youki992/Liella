<div align="center">

Liella 是一个在Linux / Windows平台下运行的应急响应工具

主要用于确认本机已建立的网络连接中是否存在C2后门，或是是否存在被威胁情报标记的服务器

这个项目的名字来源于LoveLive!企划的<a href="https://zh.moegirl.org.cn/Liella!">偶像团体(Liella!)</a>

</div>

## 声明

### 本工具旨在辅助应急响应，请勿用于非法用途

## 功能

- 判断开放在公网（0.0.0.0）的危险端口
- 判断已建立连接中存在的Cobalt Strike后门
- 判断已建立连接中存在的威胁服务器

## 演示
[![Xs064x.png](https://s1.ax1x.com/2022/06/09/Xs064x.png)](https://imgtu.com/i/Xs064x)

[![Xs0RgO.png](https://s1.ax1x.com/2022/06/09/Xs0RgO.png)](https://imgtu.com/i/Xs0RgO)

## 安装使用

- 安装Python3环境
- 在代码65行中填入https://x.threatbook.cn/v5/myApi的微步API Key
[![Xs0jKg.png](https://s1.ax1x.com/2022/06/09/Xs0jKg.png)](https://imgtu.com/i/Xs0jKg)
- python3 Liella.py 启动

## 检测原理

> [CS特征分析](https://mp.weixin.qq.com/s/hNFVTRINKbBiOQiOf0WTMA)

> [微步检测分析-参考狼组安全的tig项目](https://github.com/wgpsec/tig)

## 具体检测原理

正常服务器在进行畸形请求时（即请求不带/）返回400；

- CS服务端启动端口，进行畸形请求OPTIONS HTTP/1.1时返回b'\x15\x03\x03\x00\x02\x02\n'；

- CS服务监听端口，进行畸形请求OPTIONS HTTP/1.1时返回200；

- CS服务端配置了nginx反向代理，但C2-profile的UA头默认未更改，进行请求CURL /jquery-3.3.2.slim.min.js HTTP/1.1\r\n\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko时返回404，且是Apache的404；
