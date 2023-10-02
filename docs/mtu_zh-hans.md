# 设置 MTU 值

如果想自行指定 MTU 值，计算的方法是，把设备所在网络链路的 MTU 值减去 IP 头的大小。

比如，IPoE 的网络可能是 1500，PPPoE 的网络可能是 1492。然后 IP 头大小约为 40 字节。那么，KCPTube 的 MTU 值可以如下计算：

- IPoE
    - MTU = 1500 - 40 = 1460
- PPPoE
    - MTU = 1492 - 40 = 1452

## KCPTube 通道内转发 VPN

如果想减少流量拆分，使每次发送的数据刚好匹配 MTU 值，那么可以如下计算：

VPN MTU = KCPTube MTU - KCP Header - KCPTube Header - 2 bytes (tail)

如果启用了加密选项：

> VPN MTU = 1440 - 24 - 5 - 2 = 1409

如果不启用加密选项：

> VPN MTU = 1440 - 24 - 9 - 2 = 1405
