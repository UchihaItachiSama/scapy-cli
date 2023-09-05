# scapy-cli

An interactive CLI based packet generator script, developed using Python3 and Scapy. To quickly craft and send different protocol packets on a network interface.

- [scapy-cli](#scapy-cli)
  - [Documentation](#documentation)
  - [Modules](#modules)

## Documentation

Detailed documentation containing installation steps and examples can be found in the Wiki available [here](https://github.com/UchihaItachiSama/scapy-cli/wiki).

## Modules

The script currently supports following packet generation modules

| Module | Sub-modules | Random packet</br>generation | VLAN Tagging | Multiple Flows | Class of Service (CoS)</br>marking |
| ------ | ----------- | :-------------------------: | :------------: | :--------------: | :--------------------------: |
| ICMP | <ul><li>Request</li><li>Response</li></ul> | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| ARP | <ul><li>Request</li><li>Reply</li></ul> | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| IGMP | v1<ul><li>Membership Query</li><li>Membership Report</li></ul></br>v2<ul><li>Membership Query, General</li><li>Membership Query, Group-Specific</li><li>Membership Report</li><li>Leave Group</li></ul></br>v3<ul><li>Membership Query, General</li><li>Membership Query, Group-Specific</li><li>Membership Query, Group-and-Source-Specific</li><li>Membership Report</li><li>Leave Group</li></ul> | :x: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Multicast |  | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| VXLAN | <ul><li>Vxlan - Inner ICMP</li><li>Vxlan - Inner UDP</li><li>Vxlan - Inner TCP</li><li>Vxlan - Inner ARP</li></ul> | :white_check_mark: | :x: | :white_check_mark: | :x: |
| Load PCAP File | Edit and replay<ul><li>All Packets</li><li>Specific IP flows</li><li>Specific Non-IP flows</li></ul></br>Replay the same pcap | :x: | :x: | :white_check_mark: | :x: |
