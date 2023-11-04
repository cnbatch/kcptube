# KCP Tube Parameters

|  Name   | Value  | Require |Note|
|  ----  | ----  | :----: | ---- |
| mode  | client<br>server<br>relay |Yes|Client Mode<br>Server Mode<br>Relay Node Mode|
| listen_on | domain name or IP address |No|domain name / IP address only|
| listen_port | 1 - 65535 |Yes|Port ranges can be specified when running as a server mode|
| destination_port | 1 - 65535 |Yes|Port ranges can be specified when running as a client mode|
| destination_address  | IP address, domain name |Yes|Brackets are not required when filling in an IPv6 address|
| dport_refresh  | 20 - 65535 |No|The unit is ‘second’. Not writting this option means using the default value of 60 seconds. <br>1 to 20 is treated as 20 seconds; greater than 32767 is treated as 32767 seconds. <br>Set to 0 means disable this option.|
| encryption_algorithm | AES-GCM<br>AES-OCB<br>chacha20<br>xchacha20<br>none |No    |AES-256-GCM-AEAD<br>AES-256-OCB-AEAD<br>ChaCha20-Poly1305<br>XChaCha20-Poly1305<br>No Encryption |
| encryption_password  | Any character |Depends…|…on the setting of encryption_algorithm, if the value is set and it is not none, it is required|
| udp_timeout  | 0 - 65535 |No|The unit is ‘second’. The default value is 180 seconds, set to 0 to use the default value<br>This option represents the timeout setting between UDP application ↔ kcptube|
| keep_alive  | 0 - 65535 |No | The unit is ‘second’. The default value is 0, which means that Keep Alive is disabled. This option refers to Keep Alive between two KCP endpoints.<br>Can be enabled on any side. If no response is received after 30 seconds, the channel will be closed.|
| mux_tunnels  | 0 - 65535 |No | The default value is 0, which means that multiplexing is disabled. This option means how many multiplexing tunnels between two KCP endpoints.<br>Client Mode only.|
| stun_server  | STUN Server's address |No| Cannot be used if listen_port option is port range mode|
| log_path  | The directory where the Logs are stored |No|Cannot point to the file itself|
| mtu  | Positive Integer |No|Default value is 1440|
| kcp_mtu  | Positive Integer |No|This option refers to the length of the data content within a UDP packet. <br>The value set for this option refers to the value set by calling ikcp_setmtu(). <br>Default value is 1440.|
| kcp  | manual<br>fast1 - 6<br>regular1 - 5<br> &nbsp; |Yes|Setup Manually<br>Fast Modes<br>Regular Speeds<br>(the number at the end: the smaller the value, the faster the speed)|
| kcp_sndwnd  | Positive Integer |No|See the table below for default values, which can be overridden individually|
| kcp_rcvwnd  | Positive Integer |No|See the table below for default values, which can be overridden individually|
| kcp_nodelay  | Positive Integer |Depends…|…on the setting of ‘kcp=’, if if the value is set as ‘kcp==manual’, this option is required. See the table below for default values.|
| kcp_interval  | Positive Integer |Depends…|…on the setting of ‘kcp=’, if if the value is set as ‘kcp==manual’, this option is required. See the table below for default values.|
| kcp_resend  | Positive Integer |Depends…|…on the setting of ‘kcp=’, if if the value is set as ‘kcp==manual’, this option is required. See the table below for default values.|
| kcp_nc  | yes<br>true<br>1<br>no<br>false<br>0 |Depends…|…on the setting of ‘kcp=’, if if the value is set as ‘kcp==manual’, this option is required. See the table below for default values.|
| outbound_bandwidth | Positive Integer |No|Outbound bandwidth, used to dynamically update the value of kcp_sndwnd during communication|
| inbound_bandwidth | Positive Integer |No|Inbound bandwidth, used to dynamically update the value of kcp_rcvwnd during communication|
| ipv4_only | yes<br>true<br>1<br>no<br>false<br>0 |No|If the system disables IPv6, this option must be enabled and set to yes or true or 1|
| blast | yes<br>true<br>1<br>no<br>false<br>0 |No|Packets are forwarded as quickly as possible regardless of KCP flow control settings. May lead to overload.|
| \[listener\] | N/A |Yes<br>(Relay Mode only)|Section Name of Relay Mode, KCP settings for specifying the listening mode<br>This tag represents data exchanged with the client|
| \[forwarder\] | N/A  |Yes<br>(Relay Mode only)|Section Name of Relay Mode, KCP settings for specifying the forwarding mode<br>This tag represents data exchanged with the server|
| \[custom_input\] | N/A  |No| Section Name of Custom-IP-Mapping Mode, please refer to [The Usage of Custom IP Mappings](custom_ip_mappings_en.md)|
| \[custom_input_tcp\] | N/A  |No| Section Name of Custom-IP-Mapping Mode, please refer to [The Usage of Custom IP Mappings](custom_ip_mappings_en.md)|
| \[custom_input_udp\] | N/A  |No| Section Name of Custom-IP-Mapping Mode, please refer to [The Usage of Custom IP Mappings](custom_ip_mappings_en.md)|

Note: `encryption_algorithm` and `encryption_password` must be consistent at both ends of the communication.

## outbound_bandwidth and inbound_bandwidth
Available suffixes: K / M / G

The suffix is case-sensitive, uppercase is calculated as binary (1024), lowercase is calculated as decimal (1000).

- Entering 1000 represents a bandwidth of 1000 bps

- Entering 100k represents a bandwidth of 100 kbps (100000 bps)

- Entering 100K represents a bandwidth of 100 Kbps (102400 bps)

- Entering 100M represents a bandwidth of 100 Mbps (102400 Kbps)

- Entering 1G represents a bandwidth of 1 Gbps (1024 Mbps)

Please note that it is bps (Bits Per Second), not Bps (Bytes Per Second).

This bandwidth values should not larger than your actual bandwidth, otherwise this will cause the sending window to be congested and cause blocking.

## KCP Mode Default Values
| Fast Mode    | kcp_sndwnd | kcp_rcvwnd|kcp_nodelay|kcp_interval|kcp_resend|kcp_nc |
|  ----        | :----:     | :----:    | :----:    | :----:     | :----:   |:----: |
| fast1        | 2048       |   2048    |      1    |   1        |   2      |   1   |
| fast2        | 2048       |   2048    |      2    |   1        |   2      |   1   |
| fast3        | 2048       |   2048    |      1    |   1        |   3      |   1   |
| fast4        | 2048       |   2048    |      2    |   1        |   3      |   1   |
| fast5        | 2048       |   2048    |      1    |   1        |   4      |   1   |
| fast6        | 2048       |   2048    |      2    |   1        |   4      |   1   |

| Regular Mode | kcp_sndwnd | kcp_rcvwnd|kcp_nodelay|kcp_interval|kcp_resend|kcp_nc |
|  ----        | :----:     | :----:    | :----:    | :----:     | :----:   |:----: |
| regular1     | 1024       |   1024    |      1    |   1        |   5      |   1   |
| regular2     | 1024       |   1024    |      2    |   1        |   5      |   1   |
| regular3     | 1024       |   1024    |      0    |   1        |   2      |   1   |
| regular4     | 1024       |   1024    |      0    |   15       |   2      |   1   |
| regular5     | 1024       |   1024    |      0    |   30       |   2      |   1   |

Note: If the packet loss rate is high enough (higner than 10%), kcp_nodelay=1 may better than kcp_nodelay=2. If the packet loss rate is not too high, kcp_nodelay=2 can make the network latency smoother.

If you want to reduce traffic waste and also accept a little bit more latency increase, please try choosing regular modes.<br /> 
For scenarios that do not require low latency but only need high throughput transmission, please use **regular 3 - 5**.<br /> 
Enabling `blast=1` at this time is recommended.

# Log File
After obtaining the IP address and port after NAT hole punching for the first time, and after the IP address and port of NAT hole punching change, an ip_address.txt file will be created in the Log directory (overwrite if it exists), and the IP address and port will be written in.

The obtained NAT hole punching address will be displayed on the console at the same time.

# STUN Servers
The STUN servers obtained from [NatTypeTeste](https://github.com/HMBSbige/NatTypeTester):
- stun.syncthing.net
- stun.qq.com
- stun.miwifi.com
- stun.bige0.com
- stun.stunprotocol.org

The STUN servers obtained from [Natter](https://github.com/MikeWang000000/Natter):

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

Other STUN Servers: [public-stun-list.txt](https://gist.github.com/mondain/b0ec1cf5f60ae726202e)
