# KCP Tube 参数介绍

|  名称   | 可设置值  | 必填 |备注|
|  ----  | ----  | :----: | ---- |
| mode  | client<br>server<br>relay |是|客户端<br>服务端<br>中继节点|
| listen_port | 1 - 65535 |是|以服务端运行时可以指定端口范围|
| destination_port | 1 - 65535 |是|以客户端运行时可以指定端口范围|
| destination_address  | IP地址、域名 |是|填入 IPv6 地址时不需要中括号|
| dport_refresh  | 20 - 65535 |否|单位“秒”。预设值 60 秒，小于20秒按20秒算，大于65535时按65536秒算|
| encryption_algorithm | AES-GCM<br>AES-OCB<br>chacha20<br>xchacha20<br>none |否    |AES-256-GCM-AEAD<br>AES-256-OCB-AEAD<br>ChaCha20-Poly1305<br>XChaCha20-Poly1305<br>不加密 |
| encryption_password  | 任意字符 |视情况|设置了 encryption_algorithm 且不为 none 时必填|
| udp_timeout  | 0 - 65535 |否|单位“秒”。预设值 1800 秒，设为 0 则使用预设值<br>该选项表示的是，UDP 应用程序 ↔ kcptube 之间的超时设置|
| keep_alive  | 0 - 65535 |否 | 预设值为 0，等于停用 Keep Alive<br>该选项是指两个KCP端之间的Keep Alive|
| stun_server  | STUN 服务器地址 |否|listen_port 为端口范围模式时不可使用|
| log_path  | 存放 Log 的目录 |否|不能指向文件本身|
| kcp_mtu  | 正整数 |否|预设值1440|
| kcp  | manual<br>fast1 - 4<br>regular1 - 4<br> &nbsp; |是|手动设置<br>快速<br>常速<br>(末尾数字：数值越大，速度越慢)|
| kcp_sndwnd  | 正整数 |否|预设值见下表，可以单独覆盖|
| kcp_rcvwnd  | 正整数 |否|预设值见下表，可以单独覆盖|
| kcp_nodelay  | 正整数 |视情况|kcp=manual 时必填，预设值见下表|
| kcp_interval  | 正整数 |视情况|kcp=manual 时必填，预设值见下表|
| kcp_resend  | 正整数 |视情况|kcp=manual 时必填，预设值见下表|
| kcp_nc  | yes<br>true<br>1<br>no<br>false<br>0 |视情况|kcp=manual 时必填，预设值见下表|
| outbound_bandwidth | 正整数 |否|出站带宽，用于通讯过程中动态更新 kcp_sndwnd 的值|
| inbound_bandwidth | 正整数 |否|入站带宽，用于通讯过程中动态更新 kcp_rcvwnd 的值|
| ipv4_only | yes<br>true<br>1<br>no<br>false<br>0 |否|若系统禁用了 IPv6，须启用该选项并设为 yes 或 true 或 1|
| [listener] | N/A |是<br>(仅限中继模式)|中继模式的标签，用于指定监听模式的 KCP 设置<br>该标签表示与客户端交互数据|
| [forwarder] | N/A  |是<br>(仅限中继模式)|中继模式的标签，用于指定转运模式的 KCP 设置<br>该标签表示与服务端交互数据|

## outbound_bandwidth 与 inbound_bandwidth
可用后缀：K / M / G

后缀区分大小写，大写按二进制 (1024) 计算，小写按十进制 (1000) 计算。

- 填入 1000，表示带宽为 1000 bps

- 填入 100k，表示带宽为 100 kbps (100000 bps)

- 填入 100K，表示带宽为 100 Kbps (102400 bps)

- 填入 100M，表示带宽为 100 Mbps (102400 Kbps)

- 填入 1G，表示带宽为 1 Gbps (1024 Mbps)

注意，是 bps (Bits Per Second)，不是 Bps (Bytes Per Second)。

## KCP 模式预设值
| 快速模式      | kcp_sndwnd | kcp_rcvwnd|kcp_nodelay|kcp_interval|kcp_resend|kcp_nc |
|  ----        | :----:     | :----:    | :----:    | :----:     | :----:   | ---- |
| fast1        | 2048       |   2048    |      1    |   1        |   2      |Yes|
| fast2        | 2048       |   2048    |      1    |   1        |   3      |Yes|
| fast3        | 2048       |   2048    |      1    |   5        |   2      |Yes|
| fast4        | 2048       |   2048    |      1    |   5        |   3      |Yes|

| 常速模式      | kcp_sndwnd | kcp_rcvwnd|kcp_nodelay|kcp_interval|kcp_resend|kcp_nc |
|  ----        | :----:     | :----:    | :----:    | :----:     | :----:   | ---- |
| regular1     | 1024       |   1024    |      1    |   10       |   2      |Yes|
| regular2     | 1024       |   1024    |      1    |   10       |   3      |Yes|
| regular3     | 1024       |   1024    |      0    |   10       |   2      |Yes|
| regular4     | 1024       |   1024    |      0    |   10       |   3      |Yes|

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
