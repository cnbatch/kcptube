# 更多具体示例

此处列举不同场景的示例用法，请根据实际情况调整设置、增删选项。

## 加速 OpenVPN
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

## 加速 Shadowsocks
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