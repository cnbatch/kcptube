# KCP Tube 参数介绍

|  名称   | 可设置值  | 必填 |备注|
|  ----  | ----  | :----: | ---- |
| mode  | client<br>server<br>relay |是|客户端<br>服务端<br>中继节点|
| listen_on | 域名或 IP 地址 |否|只能填写域名或 IP 地址|
| listen_port | 1 - 65535 |是|以服务端运行时可以指定端口范围|
| destination_port | 1 - 65535 |是|以客户端运行时可以指定端口范围|
| destination_address  | IP地址、域名 |是|填入 IPv6 地址时不需要中括号|
| dport_refresh  | 0 - 32767 |否|单位“秒”。不填写表示使用预设值 60 秒。<br>1 至 20 按 20 秒算，大于 32767 按 32767 秒算。<br>设为 0 表示禁用。|
| encryption_algorithm | AES-GCM<br>AES-OCB<br>chacha20<br>xchacha20<br>none |否    |AES-256-GCM-AEAD<br>AES-256-OCB-AEAD<br>ChaCha20-Poly1305<br>XChaCha20-Poly1305<br>不加密 |
| encryption_password  | 任意字符 |视情况|设置了 encryption_algorithm 且不为 none 时必填|
| udp_timeout  | 0 - 65535 |否|单位“秒”。预设值 180 秒，设为 0 则使用预设值<br>该选项表示的是，UDP 应用程序 ↔ kcptube 之间的超时设置|
| keep_alive  | 0 - 65535 |否 | 单位“秒”。预设值为 0，等于停用 Keep Alive<br>该选项是指两个KCP端之间的Keep Alive<br>可单方面启用，用于检测通道是否停止响应。若超过30秒仍未有回应，就关闭通道。|
| mux_tunnels  | 0 - 65535 |否 | 预设值为 0，等于不使用多路复用通道<br>该选项是指两个KCP端之间的多路复用通道数<br>仅限客户端启用|
| stun_server  | STUN 服务器地址 |否|listen_port 为端口范围模式时不可使用|
| log_path  | 存放 Log 的目录 |否|不能指向文件本身|
| fec  | uint8:uint8 |否|格式为 `fec=D:R`，例如可以填入 `fec=20:4`。<br>注意：D + R 的总数最大值为 255，不能超过这个数。<br>冒号两侧任意一个值为 0 表示不使用该选项。两端的设置必须相同。<br>详情请参考 [FEC使用介绍](fec_zh-hans.md)|
| mtu  | 正整数 |否|当前网络 MTU 数值，用以自动计算 kcp_mtu|
| kcp_mtu  | 正整数 |否|预设值1440。调用 ikcp_setmtu() 设置的值，亦即 UDP 数据包内数据内容的长度|
| kcp  | manual<br>fast1 - 6<br>regular1 - 5<br> &nbsp; |是|手动设置<br>快速<br>常速<br>(末尾数字：数值越小，速度越快)|
| kcp_sndwnd  | 正整数 |否|预设值见下表，可以单独覆盖|
| kcp_rcvwnd  | 正整数 |否|预设值见下表，可以单独覆盖|
| kcp_nodelay  | 正整数 |视情况|kcp=manual 时必填，预设值见下表|
| kcp_interval  | 正整数 |视情况|kcp=manual 时必填，预设值见下表|
| kcp_resend  | 正整数 |视情况|kcp=manual 时必填，预设值见下表|
| kcp_nc  | yes<br>true<br>1<br>no<br>false<br>0 |视情况|kcp=manual 时必填，预设值见下表|
| outbound_bandwidth | 正整数 |否|出站带宽，用于通讯过程中动态更新 kcp_sndwnd 的值|
| inbound_bandwidth | 正整数 |否|入站带宽，用于通讯过程中动态更新 kcp_rcvwnd 的值|
| ipv4_only | yes<br>true<br>1<br>no<br>false<br>0 |否|若系统禁用了 IPv6，须启用该选项并设为 yes 或 true 或 1|
| ipv6_only | yes<br>true<br>1<br>no<br>false<br>0 |否|忽略 IPv4 地址|
| blast | yes<br>true<br>1<br>no<br>false<br>0 |否|尝试忽略 KCP 流控设置，尽可能迅速地转发数据包。可能会导致负载过大|
| \[listener\] | N/A |是<br>(仅限中继模式)|中继模式的标签，用于指定监听模式的 KCP 设置<br>该标签表示与客户端交互数据|
| \[forwarder\] | N/A  |是<br>(仅限中继模式)|中继模式的标签，用于指定转运模式的 KCP 设置<br>该标签表示与服务端交互数据|
| \[custom_input\] | N/A  |否|自定义映射模式的标签，使用方法请参考 [自定义映射使用方法](custom_ip_mappings_zh-hans.md)|
| \[custom_input_tcp\] | N/A  |否|自定义映射模式的标签，使用方法请参考 [自定义映射使用方法](custom_ip_mappings_zh-hans.md)|
| \[custom_input_udp\] | N/A  |否|自定义映射模式的标签，使用方法请参考 [自定义映射使用方法](custom_ip_mappings_zh-hans.md)|

其中，`encryption_algorithm` 以及 `encryption_password` 在通讯的两端必须保持一致。

## outbound_bandwidth 与 inbound_bandwidth
可用后缀：K / M / G

后缀区分大小写，大写按二进制 (1024) 计算，小写按十进制 (1000) 计算。

- 填入 1000，表示带宽为 1000 bps

- 填入 100k，表示带宽为 100 kbps (100000 bps)

- 填入 100K，表示带宽为 100 Kbps (102400 bps)

- 填入 100M，表示带宽为 100 Mbps (102400 Kbps)

- 填入 1G，表示带宽为 1 Gbps (1024 Mbps)

注意，是 bps (Bits Per Second)，不是 Bps (Bytes Per Second)。

需要提醒的是，填写的带宽值不应超出实际带宽，以免造成发送窗口拥堵导致阻塞。

**重要提示**：<br>
KCPTube 会在 KCP 链路建立后的 5 秒左右，根据握手包的延迟值以及 outbound_bandwidth 与 inbound_bandwidth 的数值，计算并设置 KCP 的发送窗口大小。设置完成后的一段时间内，有很大机率出现流量大幅度波动的情况，甚至会出现流量突然降至 0，需要好几秒才能恢复。

## KCP 模式预设值
| 快速模式      | kcp_sndwnd | kcp_rcvwnd|kcp_nodelay|kcp_interval|kcp_resend|kcp_nc |
|  ----        | :----:     | :----:    | :----:    | :----:     | :----:   |:----: |
| fast1        | 2048       |   2048    |      1    |   1        |   2      |   1   |
| fast2        | 2048       |   2048    |      2    |   1        |   2      |   1   |
| fast3        | 2048       |   2048    |      1    |   1        |   3      |   1   |
| fast4        | 2048       |   2048    |      2    |   1        |   3      |   1   |
| fast5        | 2048       |   2048    |      1    |   1        |   4      |   1   |
| fast6        | 2048       |   2048    |      2    |   1        |   4      |   1   |

| 常速模式      | kcp_sndwnd | kcp_rcvwnd|kcp_nodelay|kcp_interval|kcp_resend|kcp_nc |
|  ----        | :----:     | :----:    | :----:    | :----:     | :----:   |:----: |
| regular1     | 1024       |   1024    |      1    |   1        |   5      |   1   |
| regular2     | 1024       |   1024    |      2    |   1        |   5      |   1   |
| regular3     | 1024       |   1024    |      0    |   1        |   2      |   1   |
| regular4     | 1024       |   1024    |      0    |   15       |   2      |   1   |
| regular5     | 1024       |   1024    |      0    |   30       |   2      |   1   |

其中，丢包率越高（高于 10%），kcp_nodelay=1 就比 kcp_nodelay=2 越有优势。在丢包率不特别高的情况下，kcp_nodelay=2 可使延迟抖动更为平滑。

### 模式解读（简易版）
先说结论：模式的数字越靠前，响应速度越迅速。fast 模式稍有不同，请继续阅读。

`kcp_sndwnd` 指的是发送缓冲区的大小，`kcp_rcvwnd` 指的是接收缓冲区的大小。这两项会影响到收发速率。

`kcp_nodelay` 指的是 KCP 的 `nodelay` 变量，用于选择超时重传等待时长的增长速度。原本只有 0、1 之分，0 表示不使用 KCP 自身的快速重传，1 表示启用。<br />
- 数值为 0，则简单叠加，即新的时间是上一次时间的简单乘 2。<br />
- 数值为 1，表示新的等待时间仅为上一次时间乘 1.5，而不是2。<br />
- 2023 年 5 月，KCP 原作者又增加了数值 2，类似于数值 1。区别在于，数值 1 所用的“上一次时间”来自于当前数据包自己统计的数值，而数值 2 则使用 KCP 内部单独计算的平均延迟时间。<br />
这就是为什么前面提到过“kcp_nodelay=2 可使延迟抖动更为平滑”。

`kcp_interval` 指的是 KCP 内部更新间隔，`interval` 变量。

`kcp_resend` 指的是 KCP 内部的 `fastresend` 变量值，数值为 0 则表示关闭快速重传功能。若数值不为 0，表示跨越了指定次数后就不再等待，直接重传。

`kcp_nc` 指的是 `ikcp_nodelay()` 的最后一个参数 `nc`，0 表示不关闭流控， 1 表示关闭流控。此处应当设置成 1，否则传输速度会十分缓慢。

### 大流量传输
对于低丢包环境，每个模式都适合使用，区别只在于浪费的流量是多还是少，以及最高速的上限有所不同。其中 regular3 浪费的流量没那么多。<br />
建议同时开启 `blast=1` 设置。

对于高丢包环境，请考虑叠加使用 FEC 设置。详情请参考 [FEC使用介绍](fec_zh-hans.md)

## 加密与数据校验
由于需要传送 TCP 数据，因此数据校验是不可忽略的，正如 TCP 本身那样。

无论是否加密，kcptube 都会将 MTU 缩小 2 个字节，尾附 2 字节的数据。

如果已经使用了加密选项，那么尾附的 2 字节数据就是临时生成的IV。

如果选择不使用加密功能，那么尾附的 2 字节数据就是校验码，分别为两种 8-bit 校验码：

- 纵向冗余校验 (LRC, Longitudinal Redundancy Check)
- 8-bit checksum

这是因为 kcptube 使用的 Botan 库并不附带 16-bit 校验算法，因此 kcptube 同时使用了这两种 8-bit 校验码。

这两种校验码的计算速度都足够快，简明又实用，并不是偏门的计算方式。例如 Modbus 就用到了 LRC。

需要提醒的是，使用两种校验码仍然无法 100% 避免内容错误，TCP 本身也是一样。如果确实需要精确无误，请启用加密选项。

## 多路复用 (mux_tunnels=N)
KCP Tube 虽然有“多路复用”的功能，但默认并不主动打开。在不使用该功能的情况下，每接受一个入站连接，就会创建一个对应的出站连接。

原因是为了躲避运营商的 QoS。多路复用状态下，一旦某个端口号被 QoS，就会导致共用端口号的其它会话同时受阻，直到更换端口号为止。

连接之间相互独立，即使某个端口号被 QoS，受影响的仅仅只是这一路会话，不影响其他会话。

除非被承载的程序会产生大量独立连接。在这种情况下，KCP Tube 会创建大量 KCP 通道，在通讯过程中会消耗较多的CPU资源。

如果确实要用“多路复用”功能，可以参考以下分类：

- 适合使用“多路复用”的场景：
    - 代理转发程序，例如 Shadowsocks

- 不必使用“多路复用”的场景：
    - VPN，例如
        - OpenVPN
        - Wireguard

启用“多路复用”后，KCPTube 会预创建 N 条链路，所有入站新连接都会从已有链路中传送数据，而不再单独创建新链路。此时 KCP 通道的超时时间为 30 秒。

一般来说，`mux_tunnels 设置成 3 ~ 10 就够用了，不需要设置过高的数值。

# Log 文件
在首次获取打洞后的 IP 地址与端口后，以及打洞的 IP 地址与端口发生变化后，会向 Log 目录创建 ip_address.txt 文件（若存在就覆盖），将 IP 地址与端口写进去。

获取到的打洞地址会同时显示在控制台当中。

`log_path=` 必须指向目录，不能指向文件本身。

如果不需要写入 Log 文件，那就删除 `log_path` 这一行。

# STUN Servers
从[NatTypeTeste](https://github.com/HMBSbige/NatTypeTester)找到的普通 STUN 服务器：
- stun.syncthing.net
- stun.qq.com
- stun.miwifi.com
- stun.bige0.com
- stun.stunprotocol.org

从[Natter](https://github.com/MikeWang000000/Natter)找到的STUN 服务器：

- fwa.lifesizecloud.com
- stun.isp.net.au
- stun.freeswitch.org
- stun.voip.blackberry.com
- stun.nextcloud.com
- stun.stunprotocol.org
- stun.sipnet.com
- stun.radiojar.com
- stun.sonetel.com
- stun.voipgate.com

其它 STUN 服务器：[public-stun-list.txt](https://gist.github.com/mondain/b0ec1cf5f60ae726202e)
