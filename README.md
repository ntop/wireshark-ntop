# wireshark-ntop

This repository contains open source extensions for Wireshark.

Here you can find:
* The [ntopdump extcap module](https://github.com/ntop/PF_RING/tree/dev/userland/wireshark/extcap): it can be used to open a PF_RING interface (also those that are not listed in ifconfig) or to extract traffic from a n2disk dumpset.
* The [remotentopdump extcap module](https://github.com/ntop/n2disk/tree/master/wireshark/extcap): it can be used to capture traffic from a PF_RING interface on a remote machine, or extract traffic from a remote n2disk dumpset in Wireshark.
* The [ndpi plugin](https://github.com/ntop/nDPI/tree/dev/wireshark): it shows L7 protocol information provided by nDPI to complement internal protocol decoding. In order to do this, the ndpiReader application is used to provide Wireshark nDPI protocol dissection, and the ndpi plugin interprets nDPI information.
* The sflow_tap plugin (in this folder): it shows summaries of sFlow agents flow and counter samples.
* The [Hardware Flow Offload Dissector](https://github.com/ntop/PF_RING/tree/dev/userland/wireshark/plugins) dissector: it can dissect messages produced by the hardware flow offload engine when flows are computed in hardware.

Enjoy!
