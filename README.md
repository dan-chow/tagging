This is a part of module for multi-level feedback queue scheduling. This is responsible for tagging packets for scheduler.

This benefit from conntrack table and general iptables.
You need **libnetfilter_conntrack** to operate conntrack table and **libiptc** for operating iptables in kernel.

The Makefile is tightly related to my development, better Makefile document will be shown in the future.

Besides, **uthash** is required in our project. Please refer to http://troydhanson.github.io/uthash/
