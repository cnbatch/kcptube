# KCP Tube 中继模式配置

## 配置文件示例

客户端模式示例：
```
mode=client
kcp=regular1
inbound_bandwidth=500M
outbound_bandwidth=50M
listen_port=59000
destination_port=3000-3010
destination_address=123.45.67.89
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

中继模式示例：
```
mode=relay

[listener]
kcp=regular1
inbound_bandwidth=300M
outbound_bandwidth=300M
listen_port=3000-3010
encryption_password=qwerty1234
encryption_algorithm=AES-GCM

[forwarder]
kcp=regular2
inbound_bandwidth=300M
outbound_bandwidth=300MM
destination_port=13000-13010
destination_address=87.65.43.21
encryption_password=qwerty1234
encryption_algorithm=AES-OCB
udp_timeout=10
```

服务端模式示例：
```
mode=server
kcp=regular2
inbound_bandwidth=1G
outbound_bandwidth=1G
listen_port=13000-13010
destination_port=59000
destination_address=::1
encryption_password=qwerty1234
encryption_algorithm=AES-OCB
```

留意看的话可以发现，客户端、服务端的KCP设置和加密选项都不一样。

没错，只需要正确配置中转站两侧各自的通道即可，中继节点在转发时会重新加密。

流程：
```mermaid
sequenceDiagram
    participant User's Application
    participant KCP Client
    participant KCP Relay
    participant KCP Server
    participant Server's Application
    User's Application->>KCP Client: Application Data
    Note over KCP Client: destination_port=3000-3010
    KCP Client->>KCP Relay: KCP Client Data
    KCP Client-->>KCP Relay: kcp=regular1<br/>AES-GCM
    Note over KCP Relay: [listener]<br/>listen_port=3000-3010<br/>#10;<br/>[forwarder]<br>destination_port=13000-13010
    KCP Relay->>KCP Server: KCP Client Data
    KCP Relay-->>KCP Server: kcp=regular2<br/>AES-OCB
    Note over KCP Server: listen_port=13000-13010
    KCP Server->>Server's Application: Application Data
    Server's Application->>KCP Server: Response Data
    KCP Server->>KCP Relay: KCP Server Data
    KCP Server-->>KCP Relay: kcp=regular2<br/>AES-OCB
    KCP Relay->>KCP Client: KCP Server Data
    KCP Relay-->>KCP Client: kcp=regular1<br/>AES-GCM
    KCP Client->>User's Application: Response Data
```

## 配置文件可共用选项

以下配置选项可以在`[listener]`、`[forwarder]`标签外使用：
- kcp
- kcp_rcvwnd
- kcp_sndwnd
- outbound_bandwidth
- inbound_bandwidth
- encryption_password
- encryption_algorithm
- udp_timeout
- keep_alive
- ipv4_only=1

若出现在节点标签外，就会覆盖所有节点标签内的对应值。其中`ipv4_only=1`是特例，只有`ipv4_only=1`时才覆盖，`ipv4_only=0`时并不会覆盖。

因为`ipv4_only=0`的意思是，使用默认设置，即双栈模式。

例如，可以这样写：
```
mode=relay
kcp=fast1
outbound_bandwidth=300M
inbound_bandwidth=300M
encryption_password=qwerty1234
encryption_algorithm=AES-GCM

[listener]
listen_port=3000-3010

[forwarder]
destination_port=13000-13010
destination_address=127.0.0.1
```

如果整条链路的KCP设置都一样，这样做确实可以方便不少。

## 注意事项
若需要自行配置 `udp_timeout`，请确保中继节点的 `udp_timeout` 应当大于等于服务端与客户端的 `udp_timeout` 值，以免过早清理转发链路。

## 关于节点标签
配置中继模式时，必须明确写出两个节点标签——`[listener]` 与 `[forwarder]`，不可忽略。