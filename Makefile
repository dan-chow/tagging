CC=gcc
INCLUDEDIR=include

all:
	${CC} -I ${INCLUDEDIR} /usr/lib64/libnetfilter_conntrack.so /lib64/libiptc.so.0-1.4.7 dump.c iptc.c -o dump
debug:

	${CC}  -g -I ${INCLUDEDIR} /usr/lib64/libnetfilter_conntrack.so dump.c iptc.c -o dump
