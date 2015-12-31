#include "libut/uthash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "common.h"
#include "log.h"

int main(void) {
	/*
	struct my_struct *ms;
	char *name = "abcdef";
	HASH_FIND_INT(users,name,ms);
	if(ms ==NULL) {
		ms = (struct my_struct*) malloc(sizeof(struct my_struct));
		ms->id =name;
		HASH_ADD_INT(users,id,ms);
		printf("NULL");
	}
	
	char name2[] = "abcdef";
	HASH_FIND_INT(users,name2,ms);
	if(ms != NULL) {
		printf("%s",ms->id);
	}*/

	struct HashNode arr[32];

	struct Flow flow,flow2;
	flow.l4src = htons(123);
	flow.l4dst = htons(456);
	flow.proto = 8;
	inet_aton("192.168.121.1",&flow.src);
	inet_aton("192.168.111.1",&flow.dst);

	printf_flow(&flow);
	printf("src=%s\n",inet_ntoa(flow.src));
	printf("dst=%s\n",inet_ntoa(flow.dst));

	//memcpy(&flow2,&flow,sizeof(struct Flow));

	inet_aton("192.168.121.2",&flow2.src);
	inet_aton("192.168.111.1",&flow2.dst);

	init();
	printf("insert result=%d\n",insert_flow(&flow,time((time_t*)NULL)));
	printf("insert result=%d\n",lookup_flow(&flow));
	printf("insert result=%d\n",insert_flow(&flow2,time((time_t*)NULL)));
	printf("insert result=%d\n",lookup_flow(&flow2));
	printf_flow(&flow2);
	printf_flow(&flow);
	sleep(5);
	printf("insert result=%d\n",insert_flow(&flow,time((time_t*)NULL)));
	printf("insert result=%d\n",lookup_flow(&flow));
	sleep(5);
	printf("start iterate\n");

	iterate_flow();
	
	int num = remove_flows(arr,32,5,time((time_t*)NULL));
	LOG_DEBUG("DEBUG-TEST: REMOVE %d flows\n",num);
	printf("delete another\n");
	
	num = remove_flows(arr,32,5,time((time_t*)NULL));
	LOG_DEBUG("DEBUG-TEST: REMOVE %d flows\n",num);
	return 0;
}
