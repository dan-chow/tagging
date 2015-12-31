#ifndef __COMMON_H_
#define __COMMON_H_
#include <time.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "log.h"
#include <libut/uthash.h>
struct Flow {
	struct in_addr src;
	struct in_addr dst;
	uint16_t l4src;
	uint16_t l4dst;
	uint8_t proto;
};

typedef struct HashNode {
	union {
		struct HashNode *next;
		struct Flow flow;//[FLOW_SIZE];
	}key;
	uint64_t bytes;
	time_t recent;
	UT_hash_handle hh;
} HashNode;


int insert_flow(struct Flow *, uint64_t, time_t );
void init();
struct HashNode* lookup_flow(struct Flow*);
void iterate_flow();
void printf_flow(struct Flow *flow);

#endif
