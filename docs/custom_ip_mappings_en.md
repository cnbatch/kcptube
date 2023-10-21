# Custom Mapping Mode
In this mode, you can set your own mapping rules.

For security reasons, the custom mapping mode is not enabled by default and must be manually specified.

## Usage

Similar to the original usage, the only difference is that the client's listening settings and the server's target are both set to `{}`.

Client mode example:
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

Server mode example:
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

## Parameter Parsing
#### Server
Set either `destination_port` or `destination_address` to `{}`. It is recommended to specify both.

#### Client
Set either `listen_port` or `liston_on` to `{}`.

Then, set the address mappings under each tag.
- `[custom_input]` indicates that the mappings under this entry apply to both TCP and UDP.
- `[custom_input_tcp]` indicates that the mapping under this entry is only for TCP.
- `[custom_input_udp]` indicates that the mapping under this entry is only for UDP.

The mapping format uses `->` as a separator.
- The left side represents the client's listening address and port.
    - The listening address here can be left blank, indicating listening on all available interfaces.
    - The listening port must be specified.
- The right side represents the server's listening address and port.
    - Both the IP address and port must be specified.
    - The IP here represents the address the server connects to. For example, if you fill in 127.0.0.1, it means the server connects to 127.0.0.1 (i.e., the server itself).

IPv6 addresses should be enclosed in `[]`.