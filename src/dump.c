#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <signal.h>

#include "log.h"
#include "common.h"
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>
#include "iptc.h"


/*I don't know why that I only get zero when directly get l4dst, so I temporially get it through __snprintf_proto
//What a strang code
static void get_l4port_tcp(uint16_t *l4src, uint16_t *l4dst, const struct __nfct_tuple *tuple) {
	char buf[128];
	char subbuf[4][32];
	__snprintf_proto(buf,128,tuple);
	char *delim = "= ";
	char *p = strtok(buf,delim);
	int i = 0;
	while(p != NULL && i< 4) {
		//printf("%s\n",p);
		strcpy(subbuf[i],p);
		p = strtok(NULL,delim);
		i++;
	}
	*l4src = (uint16_t)atoi(subbuf[1]);
	*l4dst = (uint16_t)atoi(subbuf[3]);

}
inline static int is_established(const struct nf_conntrack* tuple) {
	char buf[32];
	__snprintf_protoinfo(buf,32,tuple);
        return strcmp("ESTABLISHED ",buf);
}
*/
/*LOG LEVEL*/

/*ATTR_SNAT_PORT, ATTR_SNAT_IPV4,  later
 * */
/*port*/
static inline uint16_t get_orig_l4src(const struct nf_conntrack*ct) {
	return nfct_get_attr_u16(ct,ATTR_ORIG_PORT_SRC);
}
static inline uint16_t get_orig_l4dst(const struct nf_conntrack*ct) {
	return nfct_get_attr_u16(ct,ATTR_ORIG_PORT_DST);
}
static inline uint16_t get_repl_l4src(const struct nf_conntrack*ct) {
	return nfct_get_attr_u16(ct,ATTR_REPL_PORT_SRC);
}
static inline uint16_t get_repl_l4dst(const struct nf_conntrack*ct) {
	return nfct_get_attr_u16(ct,ATTR_REPL_PORT_DST);
}
/*address*/
static inline uint32_t get_orig_ipv4_src(const struct nf_conntrack *ct) {
	return nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_SRC);
}
static inline uint32_t get_orig_ipv4_dst(const struct nf_conntrack *ct) {
	return nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_DST);
}
static inline uint32_t get_repl_ipv4_src(const struct nf_conntrack *ct) {
	return nfct_get_attr_u32(ct,ATTR_REPL_IPV4_SRC);
}
static inline uint32_t get_repl_ipv4_dst(const struct nf_conntrack *ct) {
	return nfct_get_attr_u32(ct,ATTR_REPL_IPV4_DST);
}
/*state*/
static inline uint8_t get_tcp_state(const struct nf_conntrack *ct) {
	return nfct_get_attr_u8(ct,ATTR_TCP_STATE);
}

/*L4 proto*/
static inline uint8_t get_l4proto(const struct nf_conntrack *ct) {
	return nfct_get_attr_u8(ct,ATTR_L4PROTO);
}
/*Bytes*/
static inline uint64_t get_orig_bytes(const struct nf_conntrack *ct) {
	return nfct_get_attr_u64(ct,ATTR_ORIG_COUNTER_BYTES);
}
static inline uint64_t get_repl_bytes(const struct nf_conntrack *ct) {
	return nfct_get_attr_u64(ct,ATTR_REPL_COUNTER_BYTES);
}

/*before add rule, we must remove previous rules installed*/
static int add_rule(struct HashNode *pnode, const struct Flow *f, uint8_t new_tag) {
	
	
	if(new_tag == DSCP_EF) 
		return 0; //This is the default tagging, we don't need insert rules
	
	if(pnode == NULL) {
		/*previous tag is DSCP_EF(default)*/
		/*add flow to hash table*/
		if(insert_flow(f,0/*we care about no bytes*/,new_tag,time((time_t*)NULL)) == NULL) {
			LOG_ERR("new flow: inserting flow error\n");
			return -1;
		}
		/*insert iptables rule*/
		if(INSERT_RULE(f->src, f->dst, new_tag, f->l4src,f->l4dst) != 0 ) {
			LOG_ERR("new flow: Inserting new rule error\n");
			return -1;
		}

	}else if(new_tag != pnode->dscp) {
		/*first, we need to delete previous one, and then add a new one*/
		//LOG_DEBUG("delete previous rule old_dscp = %d, new_tag=%d\n",pnode->dscp, new_tag);
		if(DELETE_RULE(pnode->key.flow.src, pnode->key.flow.dst, pnode->dscp, pnode->key.flow.l4src, pnode->key.flow.l4dst) != 0) {
			LOG_ERR("delete previous rule error\n");
			return -1;
		}
		/*Second, add new one*/

		if(INSERT_RULE(pnode->key.flow.src, pnode->key.flow.dst, new_tag, pnode->key.flow.l4src, pnode->key.flow.l4dst) != 0 ) {
			LOG_ERR("inserting new rule error\n");
			return -1;
		}

	}/*else new_tag == pnode->dscp, do nothing*/

	/*update time*/
	update_flow(pnode,new_tag,0/*We don't care about the bytes*/, time((time_t*)NULL));/*must be succeed*/

	return 0;

}


const static int interval = 5000; //every five seconds
static int conti = 1;

void sig_term(int signo) {
	if(signo == SIGTERM || signo == SIGINT) {
		conti = 0;
		return ;
	}
}

/*remove flows from hash table, and delte rules in mangle table*/
static void clean_up() {
	struct HashNode *buf[512];
	uint32_t num;
	uint32_t i;
	struct HashNode *p;
	while(1) {
		num = remove_all_flows(buf,512);

		for(i = 0; i < num; ++i ) {
			p = buf[i];
			//whatever successful or not
			DELETE_RULE(p->key.flow.src, p->key.flow.dst, p->dscp, p->key.flow.l4src, p->key.flow.l4dst); //
			free_node(p);
		}


		if(num < 512)
			break;
	}

	remove_default_rule();


}

 
static int cb(enum nf_conntrack_msg_type type,
		struct nf_conntrack *ct,
		void *data
	    ) {
	char buf[1024];
	//LOG_DEBUG("begin in cb\n");
	uint8_t proto = get_l4proto(ct);
	uint8_t state = get_tcp_state(ct);
	/*only attention to established TCP connections*/
	if(proto != TCP_PROTO)
	 return NFCT_CB_CONTINUE;

	switch(state) {
		case TCP_CONNTRACK_ESTABLISHED:
		case TCP_CONNTRACK_CLOSE_WAIT:
		case TCP_CONNTRACK_FIN_WAIT:
			break;
		default:
			return NFCT_CB_CONTINUE;
	};
	
	//LOG_DEBUG("established tcp connections got!!\n");

	struct in_addr orig_src = {.s_addr = get_orig_ipv4_src(ct)};
	struct in_addr orig_dst = {.s_addr = get_orig_ipv4_dst(ct)};
	uint16_t orig_l4src = get_orig_l4src(ct);
	uint16_t orig_l4dst = get_orig_l4dst(ct);
	uint64_t orig_bytes = get_orig_bytes(ct);
	
	struct in_addr repl_src = {.s_addr = get_repl_ipv4_src(ct)};
	struct in_addr repl_dst = {.s_addr = get_repl_ipv4_dst(ct)};
	uint16_t repl_l4src = get_repl_l4src(ct);
	uint16_t repl_l4dst = get_repl_l4dst(ct);
	uint64_t repl_bytes = get_repl_bytes(ct);

	uint64_t total_bytes = repl_bytes + orig_bytes;

	//LOG_DEBUG("got neccessary data\n");
	
	struct Flow orig_flow  = {
		.src = orig_src,
		.dst = orig_dst,
		.proto = proto,
		.l4src = orig_l4src,
		.l4dst = orig_l4dst,
	};
	struct HashNode *prev = lookup_flow(&orig_flow);
	//LOG_DEBUG("DEBUG:lookup result = %p\n",prev);
	if(total_bytes < LEVEL_1) {
	        /*mice flow */
		LOG_DEBUG("lower level_1 (%ld):",total_bytes);
		printf_flow(&orig_flow);
		return NFCT_CB_CONTINUE;
	}else if(total_bytes > LEVEL_2) {
		/*  bytes > LEVEL_2 */
		/*==NULL, unlikely*/
		LOG_DEBUG("Over level_2 (%ld):",total_bytes);
		printf_flow(&orig_flow);
		if(add_rule(prev,&orig_flow,DSCP_BE) != 0) {

			return NFCT_CB_STOP;
		}
	}else {
		/*LEVEL_1 < bytes < LEVEL_2*/
		/*==NULL, unlikely*/
		LOG_DEBUG("between level_1 and level_2 (%ld):",total_bytes);
		printf_flow(&orig_flow);
		if(add_rule(prev,&orig_flow, DSCP_PHB) != 0) {

			return NFCT_CB_STOP;
		}
	}
	
	//printf("reply flow:");
	//printf_flow(&repl_flow);

	

	/*why printf cause segment fault: It is caused by inet_ntoa, maybe a static memory allocated in that function*/
	//printf("orig: srcip=%s,",inet_ntoa(orig_src));
	//printf("dstip=%d,",inet_ntoa(orig_dst));
	//printf("srcport=%u,dstport=%u,bytes=%ld\n",orig_l4src,orig_l4dst,orig_bytes);
	//printf("repl: srcip=%s,dstip=%s,srcport=%u,dstport=%u,bytes=%ld\n",inet_ntoa(repl_src),inet_ntoa(repl_dst),repl_l4src,repl_l4dst,repl_bytes);

	return NFCT_CB_CONTINUE;
}

struct nfct_filter* create_own_filter() {
	struct nfct_filter* filter = nfct_filter_create();
	if(!filter) 
		return NULL;

	/**only TCP*/
	nfct_filter_add_attr_u32(filter,NFCT_FILTER_L4PROTO,IPPROTO_TCP);

	/*only establised TCP connections*/
	struct nfct_filter_proto filter_proto = {
		.proto = IPPROTO_TCP,
		.state = TCP_CONNTRACK_ESTABLISHED | TCP_CONNTRACK_TIME_WAIT
       	};

	nfct_filter_add_attr(filter,NFCT_FILTER_L4PROTO_STATE,&filter_proto);

	/*ignore whatever comes from loopback: 127.0.0.1*/
/*
	struct nfct_filter_ipv4 filter_ipv4 = {
		.addr = ntohl(inet_addr("127.0.0.1")),
		.mask = 0xffffffff
	};
	nfct_filter_set_logic(filter,NFCT_FILTER_SRC_IPV4,NFCT_FILTER_LOGIC_NEGATIVE);
	nfct_filter_add_attr(filter,NFCT_FILTER_SRC_IPV4,&filter_ipv4);
*/
	/*TODO:ignore all of ipv6: */

	/*
	struct nfct_filter_ipv6 filter_ipv6 = {
		.addr = {0x0,0x0,0x0,0x01},
		.mask = {0xffffffff,0xffffffff,0xffffffff,0xffffffff}
	};
	nfct_filter_set_logic(filter,NFCT_FILTER_SRC_IPV6,NFCT_FILTER_LOGIC_NEGATIVE);
	nfct_filter_add_attr(filter,NFCT_FILTER_SRC_IPV6,&filter_ipv6);
        */
        return filter;

}

int main(void) {
	int ret;
	u_int32_t family = AF_INET;
	struct nfct_handle *h;
	time_t start, now;

	if(signal(SIGTERM,sig_term)==SIG_ERR) {
		LOG_ERR("register a signal function error\n");
		return -1;
	}
	if(signal(SIGINT,sig_term)==SIG_ERR) {
		LOG_ERR("register a signal function error\n");
		return -1;
	}

	h = nfct_open(CONNTRACK,0);
	//h = nfct_open(CONNTRACK,NF_NETLINK_CONNTRACK_NEW|NF_NETLINK_CONNTRACK_UPDATE);
	if(!h) {
		LOG_ERR("nfct_open");
		return -1;
	}
	/*inital buffers*/
	init();
	//Filter dosen't work, I don't know why. So I leave it alone temporially.
	/*
	struct nfct_filter *filter = create_own_filter();
	if(!filter) {
		perror("create filter");
		return -1;
	}
	if(nfct_filter_attach(nfct_fd(h),filter) == -1) {
		perror("nfct_filter_attach");
		return 0;
	}
	
	printf("after attach\n");
	//nfct_filter_destroy(filter);
	*/
	
	nfct_callback_register(h,NFCT_T_ALL,cb,NULL);

	/*add default rule*/
	if(rule_init() != 0 ) {
		LOG_ERR("Failed to initialize rule \n");
		conti = 0;
	}
	while(conti) {
		start = time((time_t*)NULL);
		//LOG_DEBUG("start time=%d\n",start);
		ret = nfct_query(h,NFCT_Q_DUMP,&family);
		//ret = nfct_send(h,NFCT_Q_DUMP,a);//,NFCT_Q_DUMP,&family);
		//ret = nfct_catch(h);//,NFCT_Q_DUMP,&family);

		if (ret == -1) {
			//fprintf(stderr,"error ret==-1");
			LOG_ERR("(%d)(%s)\n",ret,strerror(errno));
			break;
		}
		else
		    ;//LOG_DEBUG("OK\n");

		/*here, store, lookup and modify rules
		 * */
		now = time((time_t*)NULL);
		//LOG_DEBUG("now time=%d\n",now);
		if(remove_flows(128,20,now) < 0 ){
			LOG_ERR("ERR: failed to remove flows");
			conti = 0;
		}
		now = time((time_t*)NULL);
		sleep((interval+start-now)/1000);

		
	}
	/*
	 * nfct_filter_detach(nfct_fd(h));
	 * nfct_filter_destroy(filter);
	 */
	/* we need to delete all rules inserted, according to the content in hash table*/
	clean_up();
	//sleep(5);
	nfct_close(h);
	//ret = -1 ? exit(EXIT_FAILURE): exit(EXIT_SUCCESS);
	return 0;
}
