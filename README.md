# scapy-cli

An interactive CLI based packet generator script, developed using Python3 and Scapy. To quickly craft and send different protocol packets on a network interface.

- [scapy-cli](#scapy-cli)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
    - [Manual Installation](#manual-installation)
  - [Modules](#modules)
  - [Usage](#usage)
    - [Example showing random ICMP packet generation](#example-showing-random-icmp-packet-generation)
    - [Example showing tagged multicast packet generation](#example-showing-tagged-multicast-packet-generation)
    - [Example showing IGMP module](#example-showing-igmp-module)
    - [Example loading a pcap, editing and replaying it](#example-loading-a-pcap-editing-and-replaying-it)
    - [Vxlan Example](#vxlan-example)

## Prerequisites

- Python 3
- Scapy

## Installation

### Manual Installation

- To install Scapy from source. Clone the GitHub repo `https://github.com/secdev/scapy/` or download the zipped [release](https://github.com/secdev/scapy/releases) package file to the system.

```shell
git clone https://github.com/secdev/scapy
cd scapy

- OR -

sudo unzip scapy-2.4.5.zip
cd /path-to/scapy-2.4.5/
```

- Next copy the `byteosaurus_hex.py` script from this repository under the scapy directory and run it with sudo.

```shell
cp byteosaurus_hex.py /path-to/scapy-2.4.5/

sudo python3 /path-to/scapy-2.4.5/byteosaurus_hex.py

==================================================
Scapy based packet generator
==================================================

1 -- ICMP
2 -- ARP
3 -- IGMP
4 -- Multicast
5 -- VXLAN
6 -- Load PCAP File
7 -- Exit

Enter your choice (1-7):
```

## Modules

The script currently supports following packet generation modules

| Module | Sub-modules | Random packet</br>generation | VLAN Tagging | Multiple Flows |
| ------ | ----------- | :-------------------------: | :------------: | :--------------: |
| ICMP | <ul><li>Request</li><li>Response</li></ul> | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| ARP | <ul><li>Request</li><li>Reply</li></ul> | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| IGMP | v1<ul><li>Membership Query</li><li>Membership Report</li></ul></br>v2<ul><li>Membership Query, General</li><li>Membership Query, Group-Specific</li><li>Membership Report</li><li>Leave Group</li></ul></br>v3<ul><li>Membership Query, General</li><li>Membership Query, Group-Specific</li><li>Membership Query, Group-and-Source-Specific</li><li>Membership Report</li><li>Leave Group</li></ul> | :x: | :white_check_mark: | :white_check_mark: |
| Multicast |  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| VXLAN | <ul><li>Vxlan - Inner ICMP</li><li>Vxlan - Inner UDP</li><li>Vxlan - Inner TCP</li><li>Vxlan - Inner ARP</li></ul> | :white_check_mark: | :x: | :white_check_mark: |
| Load PCAP File | Edit and replay<ul><li>All Packets</li><li>Specific IP flows</li><li>Specific Non-IP flows</li></ul></br>Replay the same pcap | :x: | :x: | :white_check_mark: |

## Usage

- The script provides interactive interface for all packet generation modules and loading/replaying packet capture files.

- Example run:

```shell
[admin@switch ~]$ sudo python3 /path-to/scapy-2.4.5/byteosaurus_hex.py

==================================================
Scapy based packet generator
==================================================

1 -- ICMP
2 -- ARP
3 -- IGMP
4 -- Multicast
5 -- VXLAN
6 -- Load PCAP File
7 -- Exit

Enter your choice (1-7):
```

### Example showing random ICMP packet generation

```shell
==================================================
Scapy based packet generator
==================================================

1 -- ICMP
2 -- ARP
3 -- IGMP
4 -- Multicast
5 -- VXLAN
6 -- Load PCAP File
7 -- Exit

Enter your choice (1-7): 1
Enter the number of flows > 1

Building flow number [ 1 ]:

Random ICMP Packet? (y/n) > y
ICMP Type (req/reply) > req
Count (c for continous) > 10
Source Interface > et1_1
2022-05-05 12:37:44,297: INFO: ICMP packet built
###[ Ethernet ]###
  dst       = 98:c2:ae:55:b5:8b
  src       = 28:99:3a:99:f1:1d
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = None
     tos       = 0x0
     len       = None
     id        = 1
     flags     =
     frag      = 0
     ttl       = 138
     proto     = icmp
     chksum    = None
     src       = 172.16.166.78
     dst       = 172.24.208.175
     \options   \
###[ ICMP ]###
        type      = echo-request
        code      = 0
        chksum    = None
        id        = 0x302
        seq       = 0x0
###[ Raw ]###
           load      = 'uM>x\xbd|\xdb\xc4&\x7fC9<^\x91G\xfbBQK\xc5\xca9\nq",Y5A\xd2\x84T\xd3\r\xa5L1\xe6\x89Th!)\x9b|\xf3\xbf\xbd\x95Cw\xf2E[N\x0b\x91\x89\xfex\xfdT\x9d'

2022-05-05 12:37:44,300: INFO: Sending out all flows
2022-05-05 12:37:44,379: INFO: Done sending all flows
2022-05-05 12:37:44,401: INFO: Module completed
```

### Example showing tagged multicast packet generation

```shell
==================================================
Scapy based packet generator
==================================================

1 -- ICMP
2 -- ARP
3 -- IGMP
4 -- Multicast
5 -- VXLAN
6 -- Load PCAP File
7 -- Exit

Enter your choice (1-7): 4
Enter the number of flows > 1

Building flow number [ 1 ]:

Random Multicast Packet? (y/n) > n
Source MAC (de:ad:be:ef:ca:fe) > 00:1b:11:10:26:11
Source IP > 192.168.1.2
Destination IP > 239.255.255.250
UDP Source Port > 6001
UDP Destination Port > 6001
Tag (y/n) > y
VLAN Tag (x,y) > 10
Count (c for continous) > 10
Source Interface > et1_1
2022-05-05 12:39:07,129: INFO: UDP Packet built
###[ Ethernet ]###
  dst       = 01:00:5e:7f:ff:fa
  src       = 00:1b:11:10:26:11
  type      = n_802_1Q
###[ 802.1Q ]###
     prio      = 0
     id        = 0
     vlan      = 10
     type      = IPv4
###[ IP ]###
        version   = 4
        ihl       = None
        tos       = 0x0
        len       = None
        id        = 1
        flags     =
        frag      = 0
        ttl       = 71
        proto     = udp
        chksum    = None
        src       = 192.168.1.2
        dst       = 239.255.255.250
        \options   \
###[ UDP ]###
           sport     = 6001
           dport     = 6001
           len       = None
           chksum    = None
###[ Raw ]###
              load      = '.\xea/\xa3^\xb5(\x8b\xb2\x9cp\x0f\x08\x84\x01C\x8d\xe8\xcd\x18\xd9\xbd\xbcn\x8dMH\xda\xea\x8eJ\xb8\x92\xf2\x16\xe1cU\xaf5\xbc\r\xbf\xfa>,\x11\x1fdm\xa5\x07(7\xe7+\\Ck%\xfa\xd8\x93\xe6'

2022-05-05 12:39:07,143: INFO: Sending out all flows
2022-05-05 12:39:07,215: INFO: Done sending all flows
2022-05-05 12:39:07,238: INFO: Module completed
```

### Example showing IGMP module

```shell
==================================================
Scapy based packet generator
==================================================

1 -- ICMP
2 -- ARP
3 -- IGMP
4 -- Multicast
5 -- VXLAN
6 -- Load PCAP File
7 -- Exit

Enter your choice (1-7): 3
Enter the number of flows > 1

Building flow number [ 1 ]:

IGMP Version (v1/v2/v3) > v3

IGMP Message Type:

1 -- Membership Query, General
2 -- Membership Query, Group-Specific
3 -- Membership Query, Group-and-Source-Specific
4 -- Membership Report
5 -- Leave Group

Enter your choice (1-5) > 4
Sender MAC (de:ad:be:ef:ca:fe) > 00:1c:73:01:a9:49
Sender IP > 192.168.1.101
Tag (y/n) > y
VLAN Tag > 10
Number of group records > 2

Group record 1:
Multicast Address > 239.1.1.1

Record Type:

1 -- Mode Is Include
2 -- Mode Is Exclude
3 -- Change To Include Mode
4 -- Change To Exclude Mode
5 -- Allow New Sources
6 -- Block Old Sources

Enter your choice (1-6) > 1
Source addresses (IP1,IP2) > 1.1.1.1,2.2.2.2

Group record 2:
Multicast Address > 239.1.1.2

Record Type:

1 -- Mode Is Include
2 -- Mode Is Exclude
3 -- Change To Include Mode
4 -- Change To Exclude Mode
5 -- Allow New Sources
6 -- Block Old Sources

Enter your choice (1-6) > 5
Source addresses (IP1,IP2) > 5.5.5.5
Count (c for continous) > 10
Source Interface > et1_1
2022-05-05 13:16:32,435: INFO: IGMPv3 Membership Report
###[ Ethernet ]###
  dst       = 01:00:5e:00:00:16
  src       = 00:1c:73:01:a9:49
  type      = n_802_1Q
###[ 802.1Q ]###
     prio      = 0
     id        = 0
     vlan      = 10
     type      = IPv4
###[ IP ]###
        version   = 4
        ihl       = None
        tos       = 0xc0
        len       = None
        id        = 1
        flags     =
        frag      = 0
        ttl       = 1
        proto     = igmp
        chksum    = None
        src       = 192.168.1.101
        dst       = 224.0.0.22
        \options   \
         |###[ IP Option Router Alert ]###
         |  copy_flag = 1
         |  optclass  = control
         |  option    = router_alert
         |  length    = 4
         |  alert     = router_shall_examine_packet
###[ IGMPv3 ]###
           type      = Version 3 Membership Report
           mrcode    = 0
           chksum    = None
###[ IGMPv3mr ]###
              res2      = 0x0
              numgrp    = 2
              \records   \
               |###[ IGMPv3gr ]###
               |  rtype     = Mode Is Include
               |  auxdlen   = 0
               |  numsrc    = 2
               |  maddr     = 239.1.1.1
               |  srcaddrs  = [1.1.1.1, 2.2.2.2]
               |###[ IGMPv3gr ]###
               |  rtype     = Allow New Sources
               |  auxdlen   = 0
               |  numsrc    = 1
               |  maddr     = 239.1.1.2
               |  srcaddrs  = [5.5.5.5]

2022-05-05 13:16:32,439: INFO: Sending out all flows
2022-05-05 13:16:32,563: INFO: Done sending all flows
2022-05-05 13:16:32,594: INFO: Module completed
```

### Example loading a pcap, editing and replaying it

```shell
==================================================
Scapy based packet generator
==================================================

1 -- ICMP
2 -- ARP
3 -- IGMP
4 -- Multicast
5 -- VXLAN
6 -- Load PCAP File
7 -- Exit

Enter your choice (1-7): 6
Path to pcap file > /absolute-path/scapy-test-cap.pcap
2022-05-05 13:18:33,590: INFO: Pcap file loaded successfully!

Select action:

1 -- Edit and replay all packets
2 -- Edit and replay specific IP flows
3 -- Edit and replay specific non-IP flows
4 -- Replay the same pcap

Enter your choice (1-4) > 2
2022-05-05 13:18:36,342: INFO: Following unique flows found in capture...
1 > 172.26.166.208  <----> 172.17.228.247       pkts:10
2 > 172.27.190.45   <----> 172.21.189.174       pkts:10
3 > 172.168.11.1    <----> 239.1.1.1            pkts:10
4 > 10.10.10.1      <----> 239.11.11.11         pkts:10
5 > 192.168.14.4    <----> 224.0.0.1            pkts:10
6 > 172.25.145.246  <----> 239.224.138.18       pkts:10

Select flows to modify and replay (all to modify all IP flows) > 1,2

Modify flow [  ('172.26.166.208', '172.17.228.247')  ]

Source MAC (de:ad:be:ef:ca:fe) > 00:1c:73:01:a9:49
Destination MAC > 00:23:15:1c:83:60
Source IP > 10.1.10.1
Destination IP > 20.2.20.2
Count (c for continous) > 1
Source Interface > et1_1
2022-05-05 13:19:03,773: INFO: Packets after change...
0000 Ether / IP / ICMP 10.1.10.1 > 20.2.20.2 echo-reply 0 / Raw
0001 Ether / IP / ICMP 10.1.10.1 > 20.2.20.2 echo-reply 0 / Raw
0002 Ether / IP / ICMP 10.1.10.1 > 20.2.20.2 echo-reply 0 / Raw
0003 Ether / IP / ICMP 10.1.10.1 > 20.2.20.2 echo-reply 0 / Raw
0004 Ether / IP / ICMP 10.1.10.1 > 20.2.20.2 echo-reply 0 / Raw
0005 Ether / IP / ICMP 10.1.10.1 > 20.2.20.2 echo-reply 0 / Raw
0006 Ether / IP / ICMP 10.1.10.1 > 20.2.20.2 echo-reply 0 / Raw
0007 Ether / IP / ICMP 10.1.10.1 > 20.2.20.2 echo-reply 0 / Raw
0008 Ether / IP / ICMP 10.1.10.1 > 20.2.20.2 echo-reply 0 / Raw
0009 Ether / IP / ICMP 10.1.10.1 > 20.2.20.2 echo-reply 0 / Raw

Modify flow [  ('172.27.190.45', '172.21.189.174')  ]

Source MAC (de:ad:be:ef:ca:fe) > ba:ad:be:ef:ca:fe
Destination MAC > de:ad:f0:0d:ca:fe
Source IP > 192.168.1.101
Destination IP > 192.168.2.202
Count (c for continous) > 1
Source Interface > et1_1
2022-05-05 13:19:34,933: INFO: Packets after change...
0000 Ether / IP / ICMP 192.168.1.101 > 192.168.2.202 echo-request 0 / Raw
0001 Ether / IP / ICMP 192.168.1.101 > 192.168.2.202 echo-request 0 / Raw
0002 Ether / IP / ICMP 192.168.1.101 > 192.168.2.202 echo-request 0 / Raw
0003 Ether / IP / ICMP 192.168.1.101 > 192.168.2.202 echo-request 0 / Raw
0004 Ether / IP / ICMP 192.168.1.101 > 192.168.2.202 echo-request 0 / Raw
0005 Ether / IP / ICMP 192.168.1.101 > 192.168.2.202 echo-request 0 / Raw
0006 Ether / IP / ICMP 192.168.1.101 > 192.168.2.202 echo-request 0 / Raw
0007 Ether / IP / ICMP 192.168.1.101 > 192.168.2.202 echo-request 0 / Raw
0008 Ether / IP / ICMP 192.168.1.101 > 192.168.2.202 echo-request 0 / Raw
0009 Ether / IP / ICMP 192.168.1.101 > 192.168.2.202 echo-request 0 / Raw
2022-05-05 13:19:34,939: INFO: Sending out modified flows...
2022-05-05 13:19:35,028: INFO: Done sending all flows
2022-05-05 13:19:35,028: INFO: Done with PCAP module
2022-05-05 13:19:35,060: INFO: Module completed
```

### Vxlan Example

```shell
==================================================
Scapy based packet generator
==================================================

1 -- ICMP
2 -- ARP
3 -- IGMP
4 -- Multicast
5 -- VXLAN
6 -- Load PCAP File
7 -- Exit

Enter your choice (1-7): 5
Enter the number of flows > 1

Building flow number [ 1 ]:

Packet Type:

1 -- Vxlan - Inner ICMP
2 -- Vxlan - Inner UDP
3 -- Vxlan - Inner TCP

Enter your choice (1-3) > 2
Generate random Vxlan UDP Packet? (y/n) > n
Inner Source MAC (de:ad:be:ef:ca:fe) > 5c:d9:98:20:2d:7e
Inner Destination MAC > 00:23:15:1c:83:60
Inner Source IP > 172.168.1.101
Inner Destination IP > 172.168.1.102
Inner UDP Source Port > 6001
Inner UDP Destination Port > 6001
Outer Source MAC (de:ad:be:af:ca:fe) >
Outer Destination MAC > de:ad:be:ef:ca:fe
Outer Source IP > 10.1.10.1
Outer Destination IP > 20.2.20.2
Outer UDP Source Port > 50001
Outer UDP Destination Port (default 4789) >
VNI > 20220
Count (c for continous) > 10
Source Interface > et1_1
2022-05-05 13:21:22,553: INFO: Inner UDP packet built
2022-05-05 13:21:22,554: INFO: Vxlan UDP Packet built
###[ Ethernet ]###
  dst       = de:ad:be:ef:ca:fe
  src       = 28:99:3a:99:f1:1d
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = None
     tos       = 0x0
     len       = None
     id        = 1
     flags     = DF
     frag      = 0
     ttl       = 27
     proto     = udp
     chksum    = None
     src       = 10.1.10.1
     dst       = 20.2.20.2
     \options   \
###[ UDP ]###
        sport     = 50001
        dport     = 4789
        len       = None
        chksum    = None
###[ VXLAN ]###
           flags     = Instance
           reserved1 = 0
           vni       = 0x4efc
           reserved2 = 0x0
###[ Ethernet ]###
              dst       = 00:23:15:1c:83:60
              src       = 5c:d9:98:20:2d:7e
              type      = IPv4
###[ IP ]###
                 version   = 4
                 ihl       = None
                 tos       = 0x0
                 len       = None
                 id        = 1
                 flags     =
                 frag      = 0
                 ttl       = 220
                 proto     = udp
                 chksum    = None
                 src       = 172.168.1.101
                 dst       = 172.168.1.102
                 \options   \
###[ UDP ]###
                    sport     = 6001
                    dport     = 6001
                    len       = None
                    chksum    = None
###[ Raw ]###
                       load      = '\\xef\\xf2\\xce\x1ayc\\xd0\\xe3 \x15\\xa14\\xc6Y\\xec\\xa8@\\xc2\x03\\xc0\\xb1\\xbf\x01T\\xb2BB\\xa7礒}\\xfdi\\xe6\\x89\x01_\\x8f\\xf4\\xd3h\\x800-\\xd6\\xf9\\xe7\\xd4k"`\x19\\xfa\x1cД\\xde\\xeeF"B)h'

2022-05-05 13:21:22,558: INFO: Sending out all flows
2022-05-05 13:21:22,683: INFO: Done sending all flows
2022-05-05 13:21:22,713: INFO: Module completed
```
