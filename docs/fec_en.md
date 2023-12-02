# FEC (Forward Error Correction) Instructions

Starting from version 20231126, KCPTube provides the FEC function to further alleviate jitter caused by packet loss.

That's right, it's Reed-Solomon coding.

## Format

The format is `fec=D:R`, where D represents the original data packets and R represents the redundant packets. The maximum total number of D + R is 255 and cannot exceed this number. As for D and R, it doesn't matter which one is bigger or smaller.

A value of 0 on either side of the colon indicates that FEC is not used.

For example, you can fill in `fec=20:4`, which means that for every 20 data packets sent, 4 redundant packets will be generated and sent.

## Precautions

The FEC settings of the sender and receiver **must** be exactly the same, otherwise FEC setting will be invalid.

## Numeric adjustment

- The amount of original data (D value) should not be too small. Setting the value too low is almost equivalent to having no effect. This value should be greater than 15.
    - Of course, greater is not better, because it will take a very long time to generate redundant data at low traffic.
    - **Game data transmission is a special case**, and the lower the value of this option, the better, preferably **set to 1**. Game traffic itself is not high, and if the packet sending interval of the game program is longer than the link latency, FEC will have no effect. As it is sensitive to latency, this value can be set to 1.
        - For gaming applications, it is preferable to set up a dedicated channel (such as a dedicated VPN tunnel) separately and avoid mixing with other applications.

- The higher amount of redundant data (R value) is not always better. Excessive amount of redundant data will cause unnecessary waste.

Therefore, you need to adjust the D value and R value according to your own traffic requirements and line packet loss rate. Generally speaking, D + R > 20 should be used.

## Interaction with KCP fast retransmission mechanism

KCP itself has a fast retransmission mechanism. You can either use the preset configuration, or you can specify and enter the kcp_resend value in KCPTube in manual mode (corresponding to the fastresend inside KCP).

If the packet loss span reaches a given number of times, automatic retransmission will be triggered.

Obviously, if the D value of `fec=D:R` is too high, the packet loss rate of the current link is high, and the fastresend value is low (for example, only 2 or 3, which is fast1 ~ fast4 mode), then the automatic retransmission may be triggered and generating a large amount of traffic before the redundant data has been generated.

For fast mode, it is recommended that the D value should not be greater than 30.

### kcp_nodelay = 1 or kcp_nodelay = 2 (fast retransmission enabled)
(fast modes and regular1-2)

- When the packet loss rate is not high (less than **5%**), there is **no need to use FEC.** Just has `blast=1` enabled can get a better effect.

- When the packet loss rate is higher than 5% but less than 10%, enable `blast=1` only is also better than FEC

- When the packet loss rate is higher than 10%, adding FEC setting is necessary.
    - But it would cause a significant waste of bandwidth, and the useful traffic is only one-third to one-fifth of total traffic.

### kcp_nodelay = 0  (No fast retransmission)
(regular3~5)

- When the packet loss rate is not high (less than **2%**), there is **no need to use FEC.** Just has `blast=1` enabled can get a better effect.
    - The advantage of regular3 is that there is less wasted traffic. It might be the best choice.
    - regular4 and regular5 are similar to regular3 at this time, but slower.

- When the packet loss rate is higher than 2% but less than 5%, enable `blast=1` only is also better than FEC

- When the packet loss rate is higher than 6%, adding FEC setting is necessary.
    - The wasted traffic increases dramatically, similar to fast mode.

## Reference settings

fast1 ~ fast6, regular1, regular2 :
- `fec=15:3`
- `fec=16:5`
- `fec=20:4`
- `fec=25:5`

regular3:
- `fec=20:4`
- `fec=25:5`
- `fec=26:6`

regular4, regular5:
- `fec=20:4`
- `fec=20:5`
- `fec=25:5`
- `fec=30:6`
- `fec=20:8`

For those who desire to set a higher D value and are not concerned about high latency, please use manual configuration mode and specify a higher kcp_resend value.

If the reason for setting a higher D value is to wrap a tunnel for VPN such as OpenVPN or WireGuard, please consider using [UDP Hop](https://github.com/cnbatch/udphop).

## FEC Source Code
The FEC Library using by KCPTube is from [fecpp](https://github.com/randombit/fecpp) with some modifications.
