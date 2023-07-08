# Specific Examples

Here is an example usage in different scenarios. Please adjust the settings and add or delete options according to the actual situation.

## Speed Up OpenVPN
Please configure OpenVPN in advance to ensure that the configuration is working.

The following assumes that the OpenVPN server is listening on port 1194, and KCPTube is running on the same server. Server's domain: `openvpn-server.domain.com`。

KCPTune Server's configuration:
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

KCPTune Client's configuration:
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

Here, it is assumed that the OpenVPN client and the KCPTube client are both running on the same machine.


And then, OpenVPN client just need to connect to port# 1194 of KCP Client.

## Transfer File with Python3 HTTP Server
Run `python3 -m http.server` first, and python3 will listen port# 8000. The following assumes that http server and KCPTube are both running on the same machine. Server's domain: `http-server.domain.com`, file to be downloaded: test.bin.

KCPTune Server's configuration:
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

KCPTune Client's configuration:
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

And then, run this command on KCPTube Client's machine: `curl http://127.0.0.1:8000/test.bin --output test.bin` to download the file.

## Speed Up Shadowsocks
The traffic forwards by Shadowsocks is socks5, so some KCPTube configuration will not the same. The following assumes that shadowsocks and KCPTube are both running on the same machine.

Assumes shadowsocks server is listening port# 8080, server's domain is ss-server.domain.com

KCPTune Server's configuration:
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

KCPTune Client's configuration:
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

Now change the configuration file of shadowsocks client, set the target as localhost:8080