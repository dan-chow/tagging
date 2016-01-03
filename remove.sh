#! /bin/sh

#the interface shoulde be specified when used in edge router(ISP router)
IN_INTF="-i eth0"
OUT_INTF="-o eth0"
#ingress
iptables -t mangle -D PREROUTING ${IN_INTF} -m dscp --dscp 46 -j MARK --set-mark 46
iptables -t mangle -D PREROUTING ${IN_INTF} -m dscp --dscp 16 -j MARK --set-mark 16
#iptables -t mangle -A PREROUTING -m mark ! --mark 0 -j ACCEPT
    
#iptables -t mangle -A PREROUTING -j MARK --set-mark 1 # we don't care about this
iptables -t mangle -D PREROUTING ${IN_INTF} -j CONNMARK --save-mark
    
    
#egress
    
iptables -t mangle -D POSTROUTING ${OUT_INTF} -j CONNMARK --restore-mark
iptables -t mangle -D POSTROUTING ${OUT_INTF} -m mark --mark 46 -j DSCP --set-dscp 46
iptables -t mangle -D POSTROUTING ${OUT_INTF} -m mark --mark 16 -j DSCP --set-dscp 16
#that's all
