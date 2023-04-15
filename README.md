# KCP Tube

## 简单介绍
[UDP Hop](https://github.com/cnbatch/udphop) 只支持转发 UDP 流量，为了能够利用 UDP 转发 TCP 流量，因此就有了KCP Tube。利用 KCP 的可靠重传保证转发的 TCP 不会丢包。

制作 KCP Tube 的另一个原因是，kcptun 只能转发 TCP 流量，但我又需要用 KCP 转发 UDP 流量。主要是为了方便玩游戏。

当然了，其实 udphup 以及 kcptube 都是同时构想出来的。所以为了方便起见，先做好了 KCP Tube，接着再在 KCP Tube 的基础上裁剪成 UDP Hop。

为了方便家宽 Full Cone NAT 用户使用，KCP Tube 以服务端基本模式运行的时候可以利用 STUN 打洞，同时支持 IPv4 与 IPv6。

## 用法
### 基本用法
`kcptube config.conf`

客户端模式示例：
```
mode=client
kcp=andante
listen_port=59000
destination_port=3000
destination_address=123.45.67.89
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

服务端模式实例：
```
mode=server
kcp=andante
listen_port=3000
destination_port=59000
destination_address=::1
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
stun_server=stun.qq.com
log_path=./
```

备注：客户端模式的 `listen_port` 不一定非要等于服务端模式的 `destination_port`，两边的端口可以不一致。

如果要指定侦听的网卡，那就指定该网卡的 IP 地址，加一行即可
```
listen_on=192.168.1.1
```

如果想要侦听多个端口、多个网卡，那就分开多个配置文件

```
kcptube config1.conf config2.conf
```

### 更灵活用法——服务端模式动态端口

客户端模式示例：
```
mode=client
kcp=andante
listen_port=6000
destination_port=3000-4000
destination_address=123.45.67.89
dport_refresh=3600
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

服务端模式示例：
```
mode=server
kcp=andante
listen_port=3000-4000
destination_port=6000
destination_address=::1
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

### 自己指定 KCP 选项

客户端模式示例：
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
dport_refresh=3600
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

服务端模式示例：
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

### 参数介绍

|  名称   | 可设置值  | 必填 |备注|
|  ----  | ----  | ---- | ---- |
| mode  | client<br>server |是|客户端<br>服务端|
| listen_port | 1 - 65535 |是|以服务端运行时可以指定端口范围|
| destination_port | 1 - 65535 |是|以客户端运行时可以指定端口范围|
| destination_address  | IP地址、域名 |是|填入 IPv6 地址时不需要中括号|
| dport_refresh  | 20 - 65535 |否|单位“秒”。预设值 60 秒，小于20秒按20秒算，大于65535时按65536秒算|
| encryption_algorithm | AES-GCM<br>AES-OCB<br>chacha20<br>xchacha20 |否    |AES-256-GCM-AEAD<br>AES-256-OCB-AEAD<br>ChaCha20-Poly1305<br>XChaCha20-Poly1305 |
| encryption_password  | 任意字符 |视情况|设置了 encryption_algorithm 时必填|
| udp_timeout  | 0 - 65535 |否|单位“秒”。预设值 1800 秒，设为 0 则使用预设值<br>该选项表示的是，UDP 应用程序 ↔ kcptube 之间的超时设置|
| keep_alive  | 0 - 65535 |否 | 预设值为 0，等于停用 Keep Alive<br>该选项是指两个KCP端之间的Keep Alive|
| stun_server  | STUN 服务器地址 |否|listen_port 为端口范围模式时不可使用|
| log_path  | 存放 Log 的目录 |否|不能指向文件本身|
| kcp_mtu  | 正整数 |否|预设值1440|
| kcp  | manual<br>largo<br>andante<br>moderato<br>allegro<br>presto<br>prestissimo |是|手动设置<br>慢速<br>较慢<br>中速<br>快速<br>急速<br>极速|
| kcp_sndwnd  | 正整数 |否|预设值见下表，可以单独覆盖|
| kcp_rcvwnd  | 正整数 |否|预设值见下表，可以单独覆盖|
| kcp_nodelay  | 0<br>1 |视情况|kcp=manual 时必填，预设值见下表|
| kcp_interval  | 正整数 |视情况|kcp=manual 时必填，预设值见下表|
| kcp_resend  | 正整数 |视情况|kcp=manual 时必填，预设值见下表|
| kcp_nc  | yes<br>true<br>1<br>no<br>false<br>0 |视情况|kcp=manual 时必填，预设值见下表|

#### KCP 模式预设值
|  模式        | kcp_sndwnd | kcp_rcvwnd|kcp_nodelay|kcp_interval|kcp_resend|kcp_nc |
|  ----       | ----        | ----      | ----      | ----       | ----     | ---- 
| largo       | 256         |   1024    |      0    |   40       |   8      |Yes|
| andante     | 256         |   1024    |      0    |   30       |   6      |Yes|
| moderato    | 256         |   1024    |      1    |   20       |   4      |Yes|
| allegro     | 512         |   2048    |      1    |   15       |   3      |Yes|
| presto      | 512         |   2048    |      1    |   10       |   2      |Yes|
| prestissimo | 512         |   2048    |      1    |   4        |   2      |Yes|

### Log 文件
在首次获取打洞后的 IP 地址与端口后，以及打洞的 IP 地址与端口发生变化后，会向 Log 目录创建 ip_address.txt 文件（若存在就覆盖），将 IP 地址与端口写进去。

获取到的打洞地址会同时显示在控制台当中。

`log_path=` 必须指向目录，不能指向文件本身。

如果不需要写入 Log 文件，那就删除 `log_path` 这一行。

### STUN Servers
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

---

## 预编译二进制
为了方便使用，目前已经提供了多个平台的二进制可执行文件：
- Windows
- FreeBSD
- Linux

预编译的二进制文件全部都是静态编译。Linux 版本基本上都是静态编译，但 libc 除外，因此准备了两个版本，一个用于 glibc，另一个用于 musl。

### Docker 镜像

对于 Linux 环境，另有提供 Docker 镜像（目前仅限 x64），下载 kcptube_docker_image.zip 并解压，再使用 `docker load -i kcptube_docker.tar` 导入。

导入后，使用方式为：
```
docker run -v /path/to/config_file.conf:/config_file.conf kcptube config_file.conf
```

例如：
```
docker run -v /home/someone/config1.conf:/config1.conf kcptube config1.conf
```

---

## 建立服务
### FreeBSD

FreeBSD 用户可将下载好的二进制文件复制到 `/usr/local/bin/`，然后运行命令
```
chmod +x /usr/local/bin/kcptube
```

本项目的 `service` 目录已经准备好相应服务文件。

1. 找到 kcptubed 文件，复制到 `/usr/local/etc/rc.d/`
2. 运行命令 `chmod +x /usr/local/etc/rc.d/kcptubed`
3. 把配置文件复制到 `/usr/local/etc/kcptubed/`
    - 记得把配置文件命名为 `config.conf`
        - 完整的路径名：`/usr/local/etc/kcptubed/config.conf`
4. 在 `/etc/rc.conf` 加一行 `kcptubed_enable="YES"`

最后，运行 `service kcptubed start` 即可启动服务

---

## 编译
编译器须支持 C++17

依赖库：

- [asio](https://github.com/chriskohlhoff/asio) ≥ 1.18.2
- [botan2](https://github.com/randombit/botan)

### Windows
请事先使用 vcpkg 安装依赖包 `asio`，一句命令即可：

```
vcpkg install asio:x64-windows asio:x64-windows-static
vcpkg install botan:x64-windows botan:x64-windows-static
```
（如果需要 ARM 或者 32 位 x86 版本，请自行调整选项）

然后用 Visual Studio 打开 `sln\punchnat.sln` 自行编译

### FreeBSD
同样，请先安装依赖项 asio 以及 botan2，另外还需要 cmake，用系统自带 pkg 即可安装：

```
pkg install asio botan2 cmake
```
接着在 build 目录当中构建
```
mkdir build
cd build
cmake ..
make
```

### NetBSD
步骤与 FreeBSD 类似，使用 [pkgin](https://www.netbsd.org/docs/pkgsrc/using.html) 安装依赖项与 cmake：
```
pkgin install asio
pkgin install botan-2
pkgin install cmake
```
构建步骤请参考上述的 FreeBSD。

注意，由于 NetBSD 自带的 GCC 版本较低，未必能成功编译出可用的二进制文件，有可能需要用 pkgin 额外安装高版本 GCC。

### Linux
步骤与 FreeBSD 类似，请用发行版自带的包管理器安装 asio 与 botan2 以及 cmake。

#### Fedora
````
dnf install asio botan2 cmake
````
接着在 build 目录当中构建
```
mkdir build
cd build
cmake ..
make
```

如果所使用发行版的 asio 版本过低，需要自行解决。

### macOS
我没苹果电脑，所有步骤请自行解决。

---

## IPv4 映射 IPv6
由于该项目内部使用的是 IPv6 单栈 + 开启 IPv4 映射地址（IPv4-mapped IPv6）来使用 IPv4 网络，因此请确保 v6only 选项的值为 0。

**正常情况下不需要任何额外设置，FreeBSD 与 Linux 以及 Windows 都默认允许 IPv4 地址映射到 IPv6。**

如果不放心，那么可以这样做
### FreeBSD
按照FreeBSD手册 [33.9.5. IPv6 and IPv4 Address Mapping](https://docs.freebsd.org/en/books/handbook/advanced-networking/#_ipv6_and_ipv4_address_mapping) 介绍，在 `/etc/rc.conf` 加一行即可
```
ipv6_ipv4mapping="YES"
```
如果还是不放心，那就运行命令
```
sysctl net.inet6.ip6.v6only=0
```

### Linux
可运行命令
```
sysctl -w net.ipv6.bindv6only=0
```
正常情况下不需要这样做，它的默认值就是 0。

## 其它注意事项
### NetBSD
使用命令
```
sysctl -w net.inet6.ip6.v6only=0
```
设置后，单栈+映射地址模式可以侦听双栈。

但由于未知的原因，它无法主动连接 IPv4 映射地址，因此 `destination_address` 只能使用 IPv6 地址。

### OpenBSD
因为 OpenBSD 彻底屏蔽了 IPv4 映射地址，所以在 OpenBSD 平台只能使用 IPv6 单栈模式。

## 数据校验
由于需要传送 TCP 数据，因此数据校验是不可忽略的，正如 TCP 本身那样。

如果已经使用了加密选项，那么就可以忽略本节内容。该项目选择的加解密算法已经附带验证能力，可以顺便保证传送内容不出错。

如果选择不使用加密功能，那么 kcptub 就会将 MTU 缩小 2 个字节，以便尾附 2 字节的校验码。

然而该项目使用的 Botan 库并不附带 16-bit 校验算法，因此该项目同时使用了两种 8-bit 校验码：
- 纵向冗余校验 (LRC, Longitudinal Redundancy Check)
- 8-bit checksum

这两种校验码的计算速度都足够快，简明又实用，并不是偏门的计算方式。例如 Modbus 就用到了 LRC。

需要提醒的是，使用两种校验码仍然无法 100% 避免内容错误，TCP 本身也是一样。如果确实需要精确无误，请启用加密选项。

## 关于代码
### 版面
代码写得很随意，想到哪写到哪，因此版面混乱。准确来说，是十分混乱。

其中有一些代码行长得像竹竿，主要是写的时候为了顺着思路所以懒得换行。毕竟我又不用 vim / emacs，我用 IDE 时，IDE 的代码区设置的文字大小不同于其他区域的文字大小，甚至字体都不一样，帮我缓解了混乱问题。

至于阅读者的感受嘛…… 那肯定会不爽。不关我事，不管了。