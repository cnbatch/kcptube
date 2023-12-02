# Specific Examples

Here are examples usage in different scenarios. Please adjust the settings and add or delete options according to the actual situation.

## Improving connection of OpenVPN
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

### If the VPN is a dedicated channel for gaming

For a dedicated channel for game data transmission, please add `blast=1` and change fast6 to a more responsive mode, like fast1 ~ fast4.

Then consider using [forward error correction (FEC)](fec_en.md) based on the packet loss rate.

### Additional matters that require attention

Due to the fact that the OpenVPN client is currently connected to the local IP address, it is necessary to selectively allow the IP address of the actual server in the routing table.

#### Soft Router
Please enable policy routing mode so that OpenVPN does not generate routing entries on its own, but rather is managed by the firewall.

#### Normal OpenVPN Client
Please add this line in the configuration file of Client:

```
route 123.45.67.89 255.255.255.255 net_gateway
```
And replace `123.45.67.89` with your server's IP.

#### High-traffic transmission

Please consider using [UDP Hop](https://github.com/cnbatch/udphop) to avoid being subject to the flow control restrictions of KCP and reduce traffic waste.

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

## Improving the use Shadowsocks
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

## Online Gaming Connection between Client and Server

In addition to using VPN for forwarding, it is also possible to directly forward to the destination server address.

Assuming the forwarding server address is `game-forward.domain.com`, and assuming the game server's domain name is `game.server.com` with port number 6000, you can do it as follows:

KCPTune Server's configuration:
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

KCPTune Client's configuration:
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

Then, modify the host file of your local network, and point the address of `game.server.com` to your local IP, which is either `127.0.0.1` or `::1`. Whether to use IPv4 or IPv6 depends on the actual situation.

### Clarification of KCP Settings

For this method of reaching the target server, you can set the `destination_address` of the VPN server mode to the IP address. The benefit of doing this is that you can choose a server with low latency to avoid selecting a target address with poor DNS performance.

The `mux_tunnels` option on the client side is optional. You can choose whether or not to include it based on actual game testing results.

Similarly, for encryption options, choose whether or not to encrypt based on device performance.

### Advise

It is more appropriate and flexible to use a soft router to do this. The soft router does not require modifying your PC's host file, only adding custom DNS entries for easy management.