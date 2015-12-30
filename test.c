#include<stdio.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/wait.h>
#include<errno.h>
#include "iptc.h"
int main(void) {

	struct in_addr src_addr, dst_addr;

	inet_aton("192.168.121.1",&src_addr);
	inet_aton("192.168.111.1",&dst_addr);
	
	uint8_t dscp = 10;
	uint16_t l4src = htons(123);
	uint16_t l4dst = htons(456);

	printf("%d\n",INSERT_RULE(src_addr,dst_addr,dscp,l4src,l4dst));
	return 0;
}
