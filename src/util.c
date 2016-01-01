#include "common.h"
#include <time.h>
#include "log.h"

static struct HashNode *flows = NULL;
static struct HashNode head_node = {0};

#define POOL_SIZE 1024

static struct HashNode hash_pool[POOL_SIZE];

void init() {
	int i = 0;

	head_node.key.next = NULL;

	for(i=POOL_SIZE-1;i>=0;--i) {
		hash_pool[i].key.next = head_node.key.next;
		head_node.key.next = &hash_pool[i];
	}
}

static struct HashNode* get_node() {
	struct HashNode *pnode = NULL;
	if(head_node.key.next == NULL)
		return NULL;

	pnode = head_node.key.next;
	head_node.key.next = head_node.key.next->key.next;

	return pnode;
}
/*free a node
 * */
void free_node(struct HashNode* node) {
	if (node == NULL)
		return;
	node->key.next = head_node.key.next;
	head_node.key.next = node;

}

/*automatically add or update*/
struct HashNode* insert_flow(const struct Flow *flow,uint64_t bytes,uint8_t dscp,time_t t) {
	struct HashNode *pnode = NULL;
	HASH_FIND_INT(flows,flow,pnode);
	if(NULL == pnode) {
		pnode = get_node();
		if(pnode == NULL)
			return NULL;
		memcpy(&pnode->key.flow,flow,sizeof(struct Flow));
		pnode->recent = t;
		pnode->bytes = bytes;

		HASH_ADD_INT(flows,key,pnode);
	}else {
		pnode->recent = t;
	}

	return pnode;
}

/*lookup */
struct HashNode *lookup_flow(struct Flow *flow) {
	struct HashNode *pnode = NULL;
	HASH_FIND_INT(flows,flow,pnode);
	return pnode;
}
/*delete, bounded by a number to avoid a long delete procedure
 *
 *
 *@nodes: return the node removed from hashtable
 *@N: the capcity of flows array. It should not be too large, or the iterately deleteion costs too much time
 *@interval: idle time for remove
 *@now: the time now
 *@
 *@return:the number of failure of deletions
 * */

int remove_flows(struct HashNode *nodes[], int N, uint32_t interval, time_t now) {
	struct HashNode *pnode = NULL, *tmp;
	int i = 0;

	HASH_ITER(hh,flows,pnode,tmp) {
		if(i >= N)
			break;
		LOG_DEBUG("now-pnod->recent = %ld\n",now - pnode->recent);
	
		if(now - pnode->recent >= interval) {
			LOG_DEBUG("Delete Flow -");
			printf_flow(&pnode->key.flow); // show flow
			HASH_DEL(flows,pnode);
			nodes[i++] = pnode;
		}
		

	}
	return i;
}
/*when return value is zero shows that all hashnodes have been removed
 * */
uint32_t remove_all_flows(struct HashNode *nodes[], int N ) {
	struct HashNode *pnode = NULL, *tmp;
	int i = 0;

	HASH_ITER(hh,flows,pnode,tmp) {
		if(i >= N)
			break;
		LOG_DEBUG("Delete Flow -");
		HASH_DEL(flows,pnode);
		nodes[i++] = pnode;
	}
	return i;
}


/*update dscp*/
int update_flow(struct HashNode *pnode, uint8_t dscp, uint64_t bytes, time_t now) {
	if(pnode == NULL)
		return -1;
	pnode->dscp = dscp;
	pnode->recent = now;//time((time_t*)NULL);
	pnode->bytes = bytes;
	return 0;
	
}

void iterate_flow() {
	struct HashNode *pnode = NULL, *tmp;

	HASH_ITER(hh,flows,pnode,tmp) {
	
			LOG_DEBUG("Iterate ");
			printf_flow(&pnode->key.flow); // show flow
		

	}

}

void printf_flow(struct Flow *flow) {

	char src_buf[16];
	snprintf(src_buf,16,"%d.%d.%d.%d",(int)(flow->src.s_addr&0xFF),(int)((flow->src.s_addr&0xFF00)>>8),(int)((flow->src.s_addr&0xFF0000)>>16),(int)((flow->src.s_addr&0xFF000000)>>24));
	LOG_DEBUG("Flow:srcIP=%s,dstIP=%s, l4src=%d, l4dst=%d, tcp\n",src_buf,
					inet_ntoa(flow->dst),htons(flow->l4src),htons(flow->l4dst));
}

