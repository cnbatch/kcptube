# Set MTU Value

If the MTU value needs to be specified, it can be calculated by subtracting the IP header size from the MTU value of the network link where the device is located.

For example, the network for IPoE may have an MTU value of 1500, while the network for PPPoE may have an MTU value of 1492. The size of the IP header is approximately 40 bytes. Thus, KCPTube's MTU value can be calculated as follows:

- IPoE
    - MTU = 1500 - 40 = 1460
- PPPoE
    - MTU = 1492 - 40 = 1452

## Transfer VPN data in KCPTube tunnel

To avoid traffic fragmentation and ensure that each packet transmitted matches the MTU value exactly, the following calculation can be used:

VPN MTU = KCPTube MTU - KCP Header - KCPTube Header - 2 bytes (tail)

If encryption options are enabled:

> VPN MTU = 1440 - 24 - 5 - 2 = 1409

If encryption options are disabled:

> VPN MTU = 1440 - 24 - 9 - 2 = 1405

