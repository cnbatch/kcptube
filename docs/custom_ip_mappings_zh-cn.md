# 自定义映射模式
在该模式下，可以自行设置映射规则。

安全起见，自定义映射模式并未默认开启，必须手动指定

## 使用方式

类似于原本的使用方式，唯一不同的是，客户端的监听设置、服务器端的目标指向，都设置成 `{}`。

客户端模式示例：
```
mode=client
kcp=regular3
inbound_bandwidth=500M
outbound_bandwidth=50M
listen_port={}
destination_port=3000
destination_address=123.45.67.89
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
mux_tunnels=3

[custom_input]
127.0.0.1:13389 -> 123.45.67.89:3389

[custom_input_tcp]
:8000 -> 127.0.0.1:8000

[custom_input_udp]
:5000 -> [::1]:5000
```

服务端模式示例：
```
mode=server
kcp=regular3
inbound_bandwidth=1G
outbound_bandwidth=1G
listen_port=3000
destination_port={}
destination_address={}
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

## 参数解析
#### 服务端
把 `destination_port` 或 `destination_address` 任意一个设为 `{}` 均可。最好两个都写。

#### 客户端
把 `listen_port` 或 `liston_on` 任意一个设为 `{}` 均可。

然后在各标签下设置地址映射。
- `[custom_input]` 表示该条目下的映射同时适用于 TCP 与 UDP。
- `[custom_input_tcp]` 表示该条目下的映射仅用于 TCP。
- `[custom_input_udp]` 表示该条目下的映射仅用于 UDP。

映射格式以 `->` 做分隔。
- 左侧为客户端监听地址及端口
    - 此处监听地址可以不填，表示监听所有可用接口
    - 监听端口必须填写
- 右侧为服务器端监听地址与端口
    - IP 地址与端口都必须填写
    - 此处的 IP 表示服务器端连接的地址，例如填写 127.0.0.1，就表示服务器自己连接 127.0.0.1 （即服务器自身）。

IPv6 地址须写在 `[]` 内。