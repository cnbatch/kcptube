# Setting MTU Value

(Applicable for versions after 20231126)

KCPTube has two parameters for setting the MTU value, which are `mtu` and `kcp_mtu`. You only need to set one of them. If both values are set, KCPTube will only use the `kcp_mtu` during runtime.

`mtu` represents the actual MTU value of the current network. To use it, please measure the MTU value of your network beforehand. Once set, KCPTube will automatically calculate the value of `kcp_mtu`.

`kcp_mtu` represents the value of the `mtu` variable within ikcp, which is the size of the data inside UDP packets.

## Forwarding VPN through KCPTube Channels

If you wish to minimize packet fragmentation and ensure that each sent data matches the MTU value precisely, please consider the following overheads and subtract the corresponding values:

KCP data header occupies 24 bytes.

KCPTube's own data header occupies 5 bytes.

If the `mux_tunnels` option is enabled, an additional 4 bytes will be used.

If FEC (Forward Error Correction) is enabled, an additional 9 bytes will be used.

Encryption Option:
- If encryption is enabled, an additional 48 bytes will be used.
- If encryption is not enabled, only an additional 2 bytes will be used (for checksum).
