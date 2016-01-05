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
	head_node.key.next = pnode->key.next;

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
	HASH_FIND(hh,flows,flow,sizeof(struct Flow),pnode);
	if(NULL == pnode) {
		pnode = get_node();
		if(pnode == NULL)
			return NULL;
		memcpy(&pnode->key.flow,flow,sizeof(struct Flow));
		pnode->recent = t;
		pnode->bytes = bytes;
		pnode->dscp = dscp;

		HASH_ADD(hh,flows,key,sizeof(union HashKey),pnode);
	}else {
		pnode->recent = t;
	}
	printf("insert_flow pnode=%p\n",pnode);

	return pnode;
}

/*lookup */
struct HashNode *lookup_flow(struct Flow *flow) {
	struct HashNode *pnode = NULL;
	HASH_FIND(hh,flows,flow,sizeof(struct Flow),pnode);
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

static int _remove_flows(struct HashNode *nodes[], int N, uint32_t interval, time_t now) {
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
/*N means the maximum number of flows during a single iteration: is Aligned to 128
 * return the nubmer revmove in reality
 * */
#define MAX_NUM_ONCE 128
int remove_flows(int N, uint32_t interval, time_t now) {
	struct HashNode *nodes[MAX_NUM_ONCE];
	struct HashNode *p;
	int i = 0;
	int j = 0;
	int success = 1;
	int real_num = 0;
	int total = 0;
	int times = N / MAX_NUM_ONCE;
	times = (N % MAX_NUM_ONCE == 0) ? (times) : (times+1);

	for(i = 0; i < times && success == 1; ++i) {
		real_num = _remove_flows(nodes,MAX_NUM_ONCE,interval,now);
		total += real_num;

		for(j = 0; j < real_num; ++j) {
			p = nodes[j];
			if(DELETE_RULE(p->key.flow.src, p->key.flow.dst, p->dscp, p->key.flow.l4src, p->key.flow.l4dst) != 0)
				success = -1;
			LOG_INFO("remove_flows(delete rule):");
			printf_flow(&p->key.flow);
			free_node(p);
		}
	}
	return success  ? total : 0- total;
	

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
	LOG_INFO("Flow:srcIP=%s,dstIP=%s, l4src=%d, l4dst=%d, tcp\n",src_buf,
					inet_ntoa(flow->dst),htons(flow->l4src),htons(flow->l4dst));
}

