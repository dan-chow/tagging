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
	uint8_t dscp;
	UT_hash_handle hh;
} HashNode;


void init();
void free_node(struct HashNode* node) ;

struct HashNode* insert_flow(const struct Flow *, uint64_t,uint8_t, time_t );
struct HashNode* lookup_flow(struct Flow*);
void iterate_flow();
int update_flow(struct HashNode *pnode, uint8_t dscp, uint64_t bytes, time_t now);
uint32_t remove_all_flows(struct HashNode *nodes[], int N ); // should be a while loop for this function

void printf_flow(struct Flow *flow);
#endif
