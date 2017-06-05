# wireshark-ntop

This repository contains open source extensions for Wireshark.

Here you can find:
* The ntopdump extcap module: it can be used to open a PF_RING interface (also those that are not listed in ifconfig) or to extract traffic from a n2disk dumpset.
* The remotentopdump extcap module: it can be used to capture traffic from a PF_RING interface on a remote machine, or extract traffic from a remote n2disk dumpset in Wireshark.
* The ndpi plugin: it shows L7 protocol information provided by nDPI to complement internal protocol decoding. In order to do this, the ndpiReader application is used to provide Wireshark nDPI protocol dissection, and the ndpi plugin interprets nDPI information.

Enjoy!
