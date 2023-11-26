# KCP Tube

**[点击此处查看简体中文版](README.md)**

## Basic Introduction
Anyone who has used home broadband from the three major telecom operators in China and needs to connect to other home networks will almost always experience UDP speed restrictions. In order to avoid the QoS targeting UDP by the three major telecom operators, I have developed a tool,  named [UDP Hop](https://github.com/cnbatch/udphop)。The principle of this tool is to regularly change the port number.

However,  UDP Hop can only forwards UDP traffic. In order to forward TCP traffic using UDP, KCP Tube is developed. The reliable retransmission of KCP ensures that the forwarded TCP packets will not be lost.

Another reason why I developed KCP Tube is that other KCP forwarding tools can only forward TCP traffic, but I need to forward UDP traffic as well. This is mainly for the convenience of playing games.

Of course, in fact, both udphop and kcptube were conceived at the same time. So for convenience, KCP Tube was first developed with a framework, and then trimmed into udphop based on KCP Tube. Then the patch code of udphop was merged back into KCP Tube in reverse.

In order to facilitate the use of Full Cone NAT users, when KCP Tube runs in server basic mode, it can use STUN to punch holes, and supports both IPv4 and IPv6.

Just like the purpose of [KCP](https://github.com/skywind3000/kcp) itself, the main goal of KCP Tube is to reduce latency, rather than focusing on transmitting large amounts of data. Can it transmit large amounts of data? Yes, but the effect may not be better than existing TCP forwarding tools.

### Supported Modes
Currently 3 modes are supported:
- Client Mode
- Servers Mode
- Relay Mode

## Usage

**Reminder:** The time of the client must be synchronized with the server and the time difference cannot exceed 255 seconds.

### All Usage
Please refer [Wiki Page](https://github.com/cnbatch/kcptube/wiki), or [Document Page](docs/README_EN.md)

You can generate a configuration file by using [KCPTube Generator](https://github.com/cnbatch/KCPTubeGenerator)

### Basic Usage
`kcptube config.conf`

Example of client mode:
```
mode=client
kcp=regular3
inbound_bandwidth=500M
outbound_bandwidth=50M
listen_port=59000
destination_port=3000
destination_address=123.45.67.89
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

Example of server mode:
```
mode=server
kcp=regular3
inbound_bandwidth=1G
outbound_bandwidth=1G
listen_port=3000
destination_port=59000
destination_address=::1
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
stun_server=stun.qq.com
log_path=./
```

Note: When connecting for the first time, the server will inform the client of its port range. Therefore, the `listen_port` of the client mode does not necessarily have to be equal to the `destination_port` of the server mode. The port numbers on both sides can be inconsistent, but the port number range written by the client cannot exceed the port number range of the server to avoid the situation where the client selects the wrong port and cannot connect.

If you want to specify the NIC to listen to, then specify the IP address of the NIC and add a line
```
listen_on=192.168.1.1
```

If you want to listen to multiple ports and multiple NICs, just run kcptube with multiple configuration files

```
kcptube config1.conf config2.conf
```

If you want to test connectivity before establish connection, just add ``--try`` option

```
kcptube --try config1.conf
```
or
```
kcptube config1.conf --try
```

### More flexible usage - Server Mode dynamic port

Example of client mode:
```
mode=client
kcp=regular3
inbound_bandwidth=500M
outbound_bandwidth=50M
listen_port=6000
destination_port=3000-4000
destination_address=123.45.67.89
dport_refresh=600
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

Example of server mode:
```
mode=server
kcp=regular3
inbound_bandwidth=1G
outbound_bandwidth=1G
listen_port=3000-4000
destination_port=6000
destination_address=::1
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

### Specify KCP options yourself

Example of client mode:
```
mode=client
kcp=manual
kcp_mtu=1400
kcp_sndwnd=512
kcp_rcvwnd=2048
kcp_nodelay=1
kcp_interval=10
kcp_resend=2
kcp_nc=true
udp_timeout=300
listen_port=6000
destination_port=3000-4000
destination_address=123.45.67.89
dport_refresh=600
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

Example of server mode:
```
mode=server
kcp=manual
kcp_mtu=1400
kcp_sndwnd=512
kcp_rcvwnd=2048
kcp_nodelay=1
kcp_interval=10
kcp_resend=2
kcp_nc=true
udp_timeout=300
listen_port=3000-4000
destination_port=6000
destination_address=::1
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

### Parameters

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
| fec  | uint8:uint8 |No|The format is `fec=D:R`, for example `fec=20:4`. <br>Note: The maximum total value of D + R is 255 and cannot exceed this number.<br>A value of 0 on either side of the colon indicates that the option is not used. Must be the same value on both side.<br>Please refer to [The Usage of FEC](docs/fec_en.md)|
| mtu  | Positive Integer |No|MTU Value of current network, is to automatically calculate the value of `kcp_mtu`|
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
| \[custom_input\] | N/A  |No| Section Name of Custom-IP-Mapping Mode, please refer to [The Usage of Custom IP Mappings](docs/custom_ip_mappings_en.md)|
| \[custom_input_tcp\] | N/A  |No| Section Name of Custom-IP-Mapping Mode, please refer to [The Usage of Custom IP Mappings](docs/custom_ip_mappings_en.md)|
| \[custom_input_udp\] | N/A  |No| Section Name of Custom-IP-Mapping Mode, please refer to [The Usage of Custom IP Mappings](docs/custom_ip_mappings_en.md)|

Note: `encryption_algorithm` and `encryption_password` must be consistent at both ends of the communication.

#### outbound_bandwidth and inbound_bandwidth
Available suffixes: K / M / G

The suffix is case-sensitive, uppercase is calculated as binary (1024), lowercase is calculated as decimal (1000).

- Entering 1000 represents a bandwidth of 1000 bps

- Entering 100k represents a bandwidth of 100 kbps (100000 bps)

- Entering 100K represents a bandwidth of 100 Kbps (102400 bps)

- Entering 100M represents a bandwidth of 100 Mbps (102400 Kbps)

- Entering 1G represents a bandwidth of 1 Gbps (1024 Mbps)

Please note that it is bps (Bits Per Second), not Bps (Bytes Per Second).

This bandwidth values should not larger than your actual bandwidth, otherwise this will cause the sending window to be congested and cause blocking.

**Important Notice**:<br>
KCPTube will calculate and set the KCP sending window size based on the delay value of the handshake packet and the values of outbound_bandwidth and inbound_bandwidth about 5 seconds after the KCP link is established. Within a period of time after the setup is completed, there is a high chance that the traffic will fluctuate significantly, or even the traffic may suddenly drop to 0, and it will take several seconds to recover.

#### KCP Mode Default Values
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

### High-traffic transmission
For low packet loss environments, each mode is suitable for use. The difference lies only in the amount of wasted traffic and the slightly different upper limit of the highest speed.<br />Among them, regular3 wastes less traffic.<br />It is recommended to enable the `blast=1` setting at the same time.

For high packet loss environments, consider using FEC settings at the same time. For more details, please refer to the [The Usage of FEC](docs/fec_en.md).

For more details, please refer to [Parameter Details](docs/parameters_en.md).

### Log File
After obtaining the IP address and port after NAT hole punching for the first time, and after the IP address and port of NAT hole punching change, an ip_address.txt file will be created in the Log directory (overwrite if it exists), and the IP address and port will be written in.

The obtained NAT hole punching address will be displayed on the console at the same time.

`log_path=` must point to a directory, not to a file itself.

If you don't need to write to the Log file, then delete the `log_path` line.

### STUN Servers
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

---

## Precompiled Binaries
For ease of use, precompiled binary executable files for multiple platforms have been provided
- Windows
- FreeBSD
- Linux

All precompiled binary files are statically compiled. The Linux version is mostly statically compiled, except for libc. Therefore, two versions have been prepared, one for glibc (2.31) and the other for musl.

### Docker Image

For Linux environments, a Docker Image is also provided (currently only for x64). Download kcptube_docker_image.zip and unzip it, then use `docker load -i kcptube_docker.tar` to import it.

After importing, use it as:
```
docker run -v /path/to/config_file.conf:/config_file.conf kcptube config_file.conf
```

Such as:
```
docker run -v /home/someone/config1.conf:/config1.conf kcptube config1.conf
```

---

## Setup a service
### FreeBSD

FreeBSD users can copy the downloaded binaries to `/usr/local/bin/`, then run the command
```
chmod +x /usr/local/bin/kcptube
```

The `service` directory of this project has prepared corresponding service files.

1. Find the kcptube file and copy it to `/usr/local/etc/rc.d/`.
2. Run the command `chmod +x /usr/local/etc/rc.d/kcptube`.
3. Copy the configuration file to `/usr/local/etc/kcptube/`.
    - Remember to name the configuration file `config.conf`.
        - Full path name: `/usr/local/etc/kcptube/config.conf`
4. Add a line `kcptube_enable="YES"` to `/etc/rc.conf`.

Finally, run service kcptube start to start the service.

---

## Compiling
The compiler must support C++17

Dependent libraries:

- [asio](https://github.com/chriskohlhoff/asio) ≥ 1.18.2
- [botan2](https://github.com/randombit/botan)

### Windows
Please use vcpkg to install the dependent packages `asio` and `botan` in advance, the command is as follows:

```
vcpkg install asio:x64-windows asio:x64-windows-static
vcpkg install botan:x64-windows botan:x64-windows-static
```
(If you need ARM or 32-bit x86 version, please adjust the options yourself)

Then open `sln\kcptube.sln` with Visual Studio and compile it yourself

### FreeBSD
Similarly, please install the dependencies `asio` and `botan2` first, and cmake is also required, which can be installed with the pkg that comes with the Freebsd system:

```
pkg install asio botan2 cmake
```
Then build in the ‘build’ directory
```
mkdir build
cd build
cmake ..
make
```

### NetBSD
The steps are similar to FreeBSD, use [pkgin](https://www.netbsd.org/docs/pkgsrc/using.html) to install dependencies and cmake:
```
pkgin install asio
pkgin install botan-2
pkgin install cmake
```
Refer to FreeBSD above for build steps.

Note that because the version of GCC that comes with NetBSD is relatively low, it may not be able to successfully compile usable binary files. It may be necessary to install a higher version of GCC with pkgin.

### Linux
The steps are similar to FreeBSD, please install `asio`, `botan2` and `cmake` with the package manager that comes with the distribution.

#### Fedora
````
dnf install asio botan2 cmake
````
Then build in the ‘build’ directory
```
mkdir build
cd build
cmake ..
make
```

If the `asio` version of the distribution you are using is too low, you need to solve it yourself.

#### Notes on Static Compilation
There are two ways

- **Way 1**

    After compiling according to the normal process, delete the newly generated kcptube binary file, and run the command
    ```
    make VERBOSE=1
    ```
    Then copy the last C++ link command from the output, and change `-lbotan-2` in the middle to the **full path** of libbotan-2.a, such as `/usr/lib/x86_64-linux-gnu/libbotan-2.a`.


- **Way 2**

    Open src/CMakeLists.txt，Change `target_link_libraries(${PROJECT_NAME} PRIVATE botan-2)` to `target_link_libraries(${PROJECT_NAME} PRIVATE botan-2 -static)`

    then it can be compiled normally. Note that if the system uses glibc, static compilation in this way will also include glibc, which will result in warnings about getaddrinfo.

### macOS
I don't have an Apple computer, please solve all the steps by yourself.

---

## Improving UDP Transmission Performance
Increasing the receive buffer can improve UDP transmission performance.
### FreeBSD
You can use the command `sysctl kern.ipc.maxsockbuf` to view the buffer size. If you need to adjust it, run the following command (replace the number with the desired value):
```
sysctl -w kern.ipc.maxsockbuf=33554434
```
Alternatively, you can write the following in `/etc/sysctl.conf`:
```
kern.ipc.maxsockbuf=33554434
```
### NetBSD & OpenBSD
You can use the command `sysctl net.inet.udp.recvspace` to view the receive buffer size. If you need to adjust it, run the following command (replace the number with the desired value):
```
sysctl -w net.inet.udp.recvspace=33554434
```
Alternatively, you can write the following in `/etc/sysctl.conf`:
```
net.inet.udp.recvspace=33554434
```
If necessary, you can also adjust the value of `net.inet.udp.sendspace`, which is for the send buffer.
### Linux
For the receive buffer, you can use the commands `sysctl net.core.rmem_max` and `sysctl net.core.rmem_default` to view the receive buffer size.

If you need to adjust it, run the following commands (replace the number with the desired value):
```
sysctl -w net.core.rmem_max=33554434
sysctl -w net.core.rmem_default=33554434
```
Alternatively, you can write the following in `/etc/sysctl.conf`:
```
net.core.rmem_max=33554434
net.core.rmem_default=33554434
```
If necessary, you can also adjust the values of `net.core.wmem_max` and `net.core.wmem_default`, which are for the send buffer settings.

## IPv4-mapped IPv6
As kcptube uses IPv6 single-stack + enabled IPv4 mapped addresses (IPv4-mapped IPv6) to simultaneously use IPv4 and IPv6 networks internally, please ensure that the value of the v6only option is 0. 

**Under normal circumstances, no additional settings are required, as FreeBSD, Linux, and Windows all allow IPv4 addresses to be mapped to IPv6 by default.**


If the system does not support IPv6 or IPv6 is disabled, please set ipv4_only=true in the configuration file, so that kcptube will fall back to using IPv4 single-stack mode.

## Other Considerations

### NetBSD
After running command
```
sysctl -w net.inet6.ip6.v6only=0
```
Single stack + mapped address mode can listen to dual stack.

However, for unknown reasons, it may not be possible to actively connect to an IPv4-mapped address may not be possible.

### OpenBSD
OpenBSD completely blocks IPv4-mapped IPv6, if you use dual-stack on the OpenBSD platform, you need to save the configuration file as two files, one of which enables ipv4_only=1, and then load both configuration files when using kcptube.

### ‘Too Many Open Files’ of multiple Operation Systems
In most cases, this kind of message only occurs on the server side, not on the client side.

If you do encounter it on the client side, please check whether the value of mux_tunnels is set too high. (please also refer to the paragraph on "Multiplexing (mux_tunnels=N)")
#### GhostBSD
In general, most BSD systems will not encounter this issue, only GhostBSD updated in the second half of 2023 will encounter it.

This is because GhostBSD has added this line in `/etc/sysctl.conf`:
```
kern.maxfiles=100000
```
This line reduces the upper limit, far below the corresponding value of the original FreeBSD.

The solution is simple, just delete or comment out this line.<br />
Alternatively, use the command `sysctl kern.maxfiles=300000` to temporarily change the limit value.

#### Linux
Since the Open Files limit for Linux systems is 1024, it's easy to encounter such problems.

Temporary solution:
1. Run the command `ulimit -n` to check the output value.
2. If the value is indeed only 1024, run the command `ulimit -n 300000`.

Permanent solution:<br />
Edit /etc/security/limits.conf and add at the end:

```
*         hard    nofile       300000
*         soft    nofile       300000
root      hard    nofile       300000
root      soft    nofile       300000
```

## Encryption and Data verification
Since TCP data transmission is required, data verification cannot be ignored, just like TCP itself.

Regardless of whether encryption is enabled or not, this program will reduce the MTU by 2 bytes and append 2-byte data at the end.

If the encryption option is used, then the 2-byte data appended at the end will be a temporarily generated IV.

If the encryption feature is not selected, the 2-byte data appended at the end will be the checksum, consisting of two different 8-bit checksums:

- Longitudinal Redundancy Check (LRC)
- 8-bit checksum

This is because the Botan library used in this program does not come with a 16-bit checksum algorithm. Therefore, this program simultaneously utilizes these two 8-bit checksums.

The calculation speed of these two checksums is fast enough, concise and practical, and is not an obscure calculation method. For example, Modbus uses LRC.

It should be reminded that using two checksums still cannot completely avoid content errors, just like TCP itself. If you really need accuracy, please enable the encryption option.

## Multiplexing (mux_tunnels=N)
The function of multiplexing is not automatically enabled by default. Without using this feature, for each incoming connection accepted, a corresponding outgoing connection is created.

The reason is to avoid the QoS of operators. Once a port number is affected by QoS in multiplexing mode, other sessions sharing the same port number will also be blocked until the port number is changed.

The connections are independent of each other. Even if a port number is affected by QoS, only this session will be affected, not other sessions.

Unless the carried program generates many independent connections. In this case, KCP Tube will create many KCP channels and consume more CPU resources during communication.

If you really need to use the ‘multiplexing’ function, you can refer to the following classifications:

- Scenarios suitable for using multiplexing:
    - Proxy forwarding programs, such as Shadowsocks

- Scenarios that do not require using multiplexing:
    - VPN, such as
        - OpenVPN
        - Wireguard

When "Multiplexing" is enabled, KCPTube will pre-create N links, and all inbound new connections will transmit data from the existing links instead of creating new links separately. At this time, the KCP channel timeout is 30 seconds.

In most cases, setting `mux_tunnels` to 3 - 10 is enough, and there is no need to set an excessively high value.


## About the codes
### TCP
To reduce latency, kcptube has enabled the TCP_NODELAY option. For some high-traffic application scenarios, this may result in a reduction in the amount of TCP data transmitted.

### KCP
KCP Tube uses a modified version of [KCP](https://github.com/skywind3000/kcp):

1. The original ‘sent data packet cache’ used a queue, and the modified version changed to use std::map, with three mapping tables: a total queue sorted by packet number, and two wait-for-resend queues, one sorted by time and the other sorted by the number of lost packets.
2. The original `flush()` function first transfers the data to be sent to the sending queue, and then completes the three things of ‘sending new data packet’, ‘resending data packet’, and ‘sending ACK packet’ in the same loop. The modified version changes to first do ‘resend data packet’ and ‘send ACK packet’, and then do ‘transfer data to be sent to sending queue’, while sending it during the transfer.
3. The original `check()` function would traverse the sending queue every time to look for the timestamp of the already arrived resend. In the modified version: the first timestamp is read from the already sorted mapping table, eliminating the searching step.

And other ‘bugs’ in the original version, will also exist in kcptube. For example:

* [如何避免缓存积累延迟的问题](https://github.com/skywind3000/kcp/issues/175)
* [求助：一些压测出现的问题， 发大包后不断累积](https://github.com/skywind3000/kcp/issues/243)

Therefore, kcptube has set a more obvious pause plan. For TCP data, when the receiving limit is reached (queue full), the reception of TCP data will be paused until there is space available to resume; for UDP data, it will be directly discarded when the receiving limit is reached.

This limit will not have much impact on application scenarios with small transfer volumes.

### Thread Pool
The thread pool used by kcptube comes from [BS::thread_pool](https://github.com/bshoshany/thread-pool), and has been slightly modified for parallel encryption and decryption processing in multiple connections.

### Layouts
I wrote these codes very casually, wherever I thought of something, I wrote it down, resulting in a messy layout. To be precise, it is extremely chaotic.

As for the feelings of the readers... well, they will definitely not be pleased. It's not my problem, I'm out!