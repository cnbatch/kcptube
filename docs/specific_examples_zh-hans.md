# 更多具体示例

此处列举不同场景的示例用法，请根据实际情况调整设置、增删选项。

## 辅助 OpenVPN 的连接
请事先配置好 OpenVPN，确保配置能连通。

以下假设 OpenVPN 服务器监听 1194 端口，KCPTube 运行于相同的机器，服务器域名是 `openvpn-server.domain.com`。

KCPTune 服务端配置：
```
mode=server
kcp=fast6
inbound_bandwidth=1G
outbound_bandwidth=1G
listen_port=21940
destination_port=1194
destination_address=::1
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

KCPTune 客户端配置：
```
mode=client
kcp=fast6
inbound_bandwidth=500M
outbound_bandwidth=50M
listen_port=1194
destination_port=21940
destination_address=openvpn-server.domain.com
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

此处假设 OpenVPN 客户端与 KCPTube 客户端都运行在同一台机器。

然后，OpenVPN 客户端程序只需要连接 KCPTube 客户端的 1194 端口即可。

### 额外注意事项

由于 OpenVPN 客户端此时连接的是本机 IP 地址，因此需要在路由表中针对性地放行实际服务器的 IP 地址。

#### 软路由
请启用策略路由模式，以便 OpenVPN 不自行生成路由条目，改由防火墙接管。

#### 普通 OpenVPN 客户端
请在客户端的配置文件中增添一项

```
route 123.45.67.89 255.255.255.255 net_gateway
```
这里的 123.45.67.89 请替换成实际服务器的 IP 地址。

## Python3 HTTP Server 传文件
首先运行 `python3 -m http.server`，此时 python3 的 http 服务器监听 8000 端口。以下假设 http 服务器及KCPTube 都运行在相同的机器，服务器域名是 `http-server.domain.com`，下载的文件为 test.bin。

KCPTune 服务端配置：
```
mode=server
kcp=fast6
inbound_bandwidth=1G
outbound_bandwidth=1G
listen_port=18000
destination_port=8000
destination_address=::1
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

KCPTune 客户端配置：
```
mode=client
kcp=fast6
inbound_bandwidth=500M
outbound_bandwidth=50M
listen_port=8000
destination_port=18000
destination_address=http-server.domain.com
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

接着，在 KCPTube 客户端的这台机器运行 `curl http://127.0.0.1:8000/test.bin --output test.bin` 即可下载文件。

## 辅助使用 Shadowsocks
由于 Shadowsocks 转发的是 socks5 流量，因此 KCPtube 的配置稍有不同。以下假设 shadowsocks 与 KCPTube 都运行在同一台机器，服务器、客户端均如此。

假设 shadowsocks 服务端监听 8080 端口，服务器域名为 ss-server.domain.com。

KCPTune 服务端配置：
```
mode=server
kcp=regular3
inbound_bandwidth=1G
outbound_bandwidth=1G
listen_port=18080
destination_port=8080
destination_address=::1
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

KCPTune 客户端配置：
```
mode=client
kcp=regular3
inbound_bandwidth=500M
outbound_bandwidth=50M
listen_port=8080
destination_port=18080
destination_address=ss-server.domain.com
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
mux_tunnels=3
```

随后改一改 shadowsocks 客户端的设置，指向本机 8080 即可。

## 联机游戏连接服务器

除了使用 VPN 转发的方式，其实还可以直接转给目标服务器地址。

假设转发服务器的地址是 `game-forward.domain.com`并假设游戏服务器的域名是 `game.server.com`、端口号是 6000，那么可以这样做：

KCPTune 服务端配置：
```
mode=server
kcp=regular3
inbound_bandwidth=1G
outbound_bandwidth=1G
listen_port=16000
destination_port=6000
destination_address=game.server.com
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

KCPTune 客户端配置：
```
mode=client
kcp=regular3
inbound_bandwidth=500M
outbound_bandwidth=50M
listen_port=6000
destination_port=16000
destination_address=game-forward.domain.com
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
mux_tunnels=3
```

然后本机网络改 Host 文件，把 `game.server.com` 的地址指向本机 IP，也就是 `127.0.0.1`，或 `::1`，至于用 IPv4 还是 IPv6，请视乎实际情况而定。

### KCP 设置说明

对于这样通向目标服务器的方式，可以把 KCP 服务器模式的 `destination_address` 设置为 IP 地址，这样做的好处是可以自行选定延迟低的服务器，以免 DNS 选了个延迟不太好的目标地址。

客户端的 `mux_tunnels` 可填可不填。请视乎游戏实测来选择写不写。

加密选项同理，请根据设备性能来选择是否加密。

### 其他说明

如果条件允许，使用软路由去做这种事情更为合适、更为灵活。软路由无须改 host 文件，只须添加自定义 DNS 条目，方便管理。