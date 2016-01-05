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



#define NFNETLINK_NOT_SUPPORTED
#ifdef NFNETLINK_NOT_SUPPORTED
#include <object.h>
#endif
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
#ifndef NFNETLINK_NOT_SUPPORTED
	return nfct_get_attr_u16(ct,ATTR_ORIG_PORT_SRC);
#else
	return ct->head.orig.l4src.all;
#endif

}
static inline uint16_t get_orig_l4dst(const struct nf_conntrack*ct) {

#ifndef NFNETLINK_NOT_SUPPORTED
	return nfct_get_attr_u16(ct,ATTR_ORIG_PORT_DST);
#else
	return ct->head.orig.l4dst.all;
#endif

}
static inline uint16_t get_repl_l4src(const struct nf_conntrack*ct) {
#ifndef NFNETLINK_NOT_SUPPORTED
	return nfct_get_attr_u16(ct,ATTR_REPL_PORT_SRC);
#else
	return ct->repl.l4src.all;
#endif

}
static inline uint16_t get_repl_l4dst(const struct nf_conntrack*ct) {
#ifndef NFNETLINK_NOT_SUPPORTED
	return nfct_get_attr_u16(ct,ATTR_REPL_PORT_DST);
#else
	return ct->repl.l4dst.all;
#endif
}
/*address*/
static inline uint32_t get_orig_ipv4_src(const struct nf_conntrack *ct) {
#ifndef NFNETLINK_NOT_SUPPORTED
	return nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_SRC);
#else
	return ct->head.orig.src.v4;
#endif
}
static inline uint32_t get_orig_ipv4_dst(const struct nf_conntrack *ct) {
#ifndef NFNETLINK_NOT_SUPPORTED
	return nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_DST);
#else
	return ct->head.orig.dst.v4;
#endif
}
static inline uint32_t get_repl_ipv4_src(const struct nf_conntrack *ct) {
#ifndef NFNETLINK_NOT_SUPPORTED
	return nfct_get_attr_u32(ct,ATTR_REPL_IPV4_SRC);
#else
	return ct->repl.src.v4;
#endif
}
static inline uint32_t get_repl_ipv4_dst(const struct nf_conntrack *ct) {
#ifndef NFNETLINK_NOT_SUPPORTED
	return nfct_get_attr_u32(ct,ATTR_REPL_IPV4_DST);
#else
	return ct->repl.dst.v4;
#endif
}
/*state*/
static inline uint8_t get_tcp_state(const struct nf_conntrack *ct) {
#ifndef NFNETLINK_NOT_SUPPORTED
	return nfct_get_attr_u8(ct,ATTR_TCP_STATE);
#else
	return ct->protoinfo.tcp.state;
#endif
}

/*L4 proto*/
static inline uint8_t get_l4proto(const struct nf_conntrack *ct) {
#ifndef NFNETLINK_NOT_SUPPORTED
	return nfct_get_attr_u8(ct,ATTR_L4PROTO);
#else
	return ct->head.orig.protonum;
#endif
}
/*Bytes*/
static inline uint64_t get_orig_bytes(const struct nf_conntrack *ct) {
#ifndef NFNETLINK_NOT_SUPPORTED
	return nfct_get_attr_u64(ct,ATTR_ORIG_COUNTER_BYTES);
#else 
	return ct->counters[__DIR_ORIG].bytes;
#endif
}
static inline uint64_t get_repl_bytes(const struct nf_conntrack *ct) {
#ifndef NFNETLINK_NOT_SUPPORTED
	return nfct_get_attr_u64(ct,ATTR_REPL_COUNTER_BYTES);
#else
	return ct->counters[__DIR_REPL].bytes;
#endif

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

static struct in_addr gw_ip = {0};

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
	//printf("msg_type==%d, %d\n",type, NFCT_T_UPDATE);
	//printf("l3proto = %u,l4proto = %u\n ",nfct_get_attr_u8(ct,ATTR_L3PROTO),get_l4proto(ct));
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
	//just care about the traffic of which the source is gateway ip
	
	if(gw_ip.s_addr != 0 && gw_ip.s_addr != orig_src.s_addr) {
		LOG_DEBUG("check between gw_ip and orig_src\n");
		return NFCT_CB_CONTINUE;
	}
	
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
		LOG_INFO("lower level_1 (%ld):",total_bytes);
		printf_flow(&orig_flow);
		return NFCT_CB_CONTINUE;
	}else if(total_bytes > LEVEL_2) {
		/*  bytes > LEVEL_2 */
		/*==NULL, unlikely*/
		LOG_INFO("Over level_2 (%ld):",total_bytes);
		printf_flow(&orig_flow);
		if(add_rule(prev,&orig_flow,DSCP_BE) != 0) {

			return NFCT_CB_STOP;
		}
	}else {
		/*LEVEL_1 < bytes < LEVEL_2*/
		/*==NULL, unlikely*/
		LOG_INFO("between level_1 and level_2 (%ld):",total_bytes);
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
/*system bits*/
#define M64
#ifdef M32
#define STR_TO_UINT64(p) strtoull(p,NULL,10)
#endif

#ifdef M64

#define STR_TO_UINT64(p) strtoul(p,NULL,10)
#endif


#ifdef NFNETLINK_NOT_SUPPORTED

#define L3PROTO_POS     1
#define L4PROTO_POS     3
#define L4STATE_POS     5

#define SRC     "src="    
#define DST     "dst="
#define L4SRC   "sport="
#define L4DST   "dport="
#define BYTE    "bytes="
#define PACKET  "packets="

#define ADDR_OFFSET     4
#define L4_OFFSET       6
#define BYTE_OFFSET     6
#define PACKET_OFFSET  8


#define FLOW_START_LABEL "src="

#define ESTABLISHED "ESTABLISHED"
#define CLOSE_WAIT  "CLOSE_WAIT"
#define FIN_WAIT    "FIN_WAIT"

char *process_layers(struct nf_conntrack *ct, char *p, const char *sep) {
	int i = 0;
	while(strstr(p,FLOW_START_LABEL) == NULL) {
		LOG_DEBUG("the %d-th, split string = %s\n",i,p);
		if( L3PROTO_POS == i) {
			ct->head.orig.l3protonum = atoi(p);
			LOG_DEBUG("l3protonum = %d\n",ct->head.orig.l3protonum);
		}else if(L4PROTO_POS == i) {
			ct->head.orig.protonum = atoi(p);
			LOG_DEBUG("protonum = %d\n",ct->head.orig.protonum);

		}else if(L4STATE_POS == i && ct->head.orig.protonum == TCP_PROTO) {
			if(strcmp(p, ESTABLISHED) == 0) {
				ct->protoinfo.tcp.state = TCP_CONNTRACK_ESTABLISHED;
			}else if(strcmp(p,CLOSE_WAIT) == 0) {
				ct->protoinfo.tcp.state = TCP_CONNTRACK_CLOSE_WAIT;
			}else if(strcmp(p,FIN_WAIT) == 0 ){
				ct->protoinfo.tcp.state = TCP_CONNTRACK_FIN_WAIT;	
			}else 
				ct->protoinfo.tcp.state = 0; //I don't care others

			LOG_DEBUG("protoinfo.tcp.state = %d\n",ct->protoinfo.tcp.state);
		}
		p = strtok(NULL,sep);

		++i;
	}

	return p;
}
/*p = "src=..."*/
char *process_orig(struct nf_conntrack *ct, char *p, const char *sep) {
	
	char *tmp = p + ADDR_OFFSET;
	struct in_addr addr;
	/*src address*/
	if(strstr(p,SRC) == NULL || inet_aton(tmp,&addr) == 0) {
		ct->head.orig.src.v4 = 0;
	}else {
		ct->head.orig.src.v4 = addr.s_addr;
		p = strtok(NULL,sep);
		LOG_DEBUG("orig-src = %s\n",inet_ntoa(addr));
	}
	
	tmp = p + ADDR_OFFSET;
	if(strstr(p,DST) == NULL || inet_aton(tmp,&addr) == 0) {
		ct->head.orig.dst.v4 = 0;
	}else {
		ct->head.orig.dst.v4 = addr.s_addr;
		p = strtok(NULL,sep);
		LOG_DEBUG("orig-dst = %s\n",inet_ntoa(addr));
	}

	tmp = p + L4_OFFSET;
	if(strstr(p,L4SRC) == NULL) {
		ct->head.orig.l4src.all = 0;
	}else {
		ct->head.orig.l4src.all = htons((short)atoi(tmp));
		LOG_DEBUG("l4src string = %s\n",tmp);
		LOG_DEBUG("orig-l4src = %d\n",ntohs(ct->head.orig.l4src.all));
		p = strtok(NULL,sep);
	}

	tmp = p + L4_OFFSET;
	if(strstr(p,L4DST) == NULL) {
		ct->head.orig.l4dst.all = 0;
	}else {
		ct->head.orig.l4dst.all = htons((short)atoi(tmp));
		LOG_DEBUG("l4dst string = %s\n",tmp);
		LOG_DEBUG("orig-l4dst = %d\n",ntohs(ct->head.orig.l4dst.all));
		p = strtok(NULL,sep);
	}
	
	tmp = p + PACKET_OFFSET;
	if(strstr(p,PACKET) == NULL) {
		ct->counters[__DIR_ORIG].packets = 0;
	}else {
		LOG_DEBUG("packets=%s\n",tmp);
		ct->counters[__DIR_ORIG].packets = STR_TO_UINT64(tmp);//atoi(tmp);
		p = strtok(NULL,sep);
		LOG_DEBUG("orig-packets = %ld\n",ct->counters[__DIR_ORIG].packets);
	}
	
	tmp = p + BYTE_OFFSET;
	if(strstr(p,BYTE) == NULL) {
		ct->counters[__DIR_ORIG].bytes = 0;
	}else {
		LOG_DEBUG("bytes=%s\n",tmp);
		ct->counters[__DIR_ORIG].bytes = STR_TO_UINT64(tmp);//atoi(tmp); 
		p = strtok(NULL,sep);
		LOG_DEBUG("orig-bytes = %ld\n",ct->counters[__DIR_ORIG].bytes);
	}	
	/* attention: strtoull, convert string to unsigned long long: as the platform of my router is 32bit*/

	
	LOG_DEBUG("end orig = %s\n",p);


	return p;
}
char *process_repl(struct nf_conntrack *ct, char *p,const  char *sep) {
	char *tmp = p + ADDR_OFFSET;
	struct in_addr addr;
	/*src address*/
	if(strstr(p,SRC) == NULL || inet_aton(tmp,&addr) == 0) {
		ct->repl.src.v4 = 0;
	}else {
		ct->repl.src.v4 = addr.s_addr;
		p = strtok(NULL,sep);
		LOG_DEBUG("repl-src = %s\n",inet_ntoa(addr));
	}

	tmp = p + ADDR_OFFSET;
	if(strstr(p,DST) == NULL || inet_aton(tmp,&addr) == 0) {
		ct->repl.dst.v4 = 0;
	}else {
		ct->repl.dst.v4 = addr.s_addr;
		p = strtok(NULL,sep);
		LOG_DEBUG("repl-dst = %s\n",inet_ntoa(addr));
	}

	tmp = p + L4_OFFSET;
	if(strstr(p,L4SRC) == NULL) {
		ct->repl.l4src.all = 0;
	}else {
		ct->repl.l4src.all = htons((short)atoi(tmp));
		p = strtok(NULL,sep);
		LOG_DEBUG("l4src string = %s\n",tmp);
		LOG_DEBUG("repl-l4src = %d\n",htons(ct->repl.l4src.all));
	}

	tmp = p + L4_OFFSET;
	if(strstr(p,L4DST) == NULL) {
		ct->repl.l4dst.all = 0;
	}else {
		ct->repl.l4dst.all = htons((short)atoi(tmp));
		p = strtok(NULL,sep);
		LOG_DEBUG("l4dst string = %s\n",tmp);
		LOG_DEBUG("repl-l4dst = %d\n",ntohs(ct->repl.l4src.all));
	}
	
	tmp = p + PACKET_OFFSET;
	if(strstr(p,PACKET) == NULL) {
		ct->counters[__DIR_REPL].packets = 0;
	}else {
		ct->counters[__DIR_REPL].packets = STR_TO_UINT64(tmp);//atoi(tmp);
		p = strtok(NULL,sep);
		LOG_DEBUG("repl-packets = %ld\n",ct->counters[__DIR_REPL].packets);

	}
	
	tmp = p + BYTE_OFFSET;
	if(strstr(p,BYTE) == NULL) {
		ct->counters[__DIR_REPL].bytes = 0;
	}else {
		ct->counters[__DIR_REPL].bytes = STR_TO_UINT64(tmp);//atoi(tmp); 
		p = strtok(NULL,sep);
		LOG_DEBUG("repl-packets = %ld\n",ct->counters[__DIR_REPL].bytes);
	}
	/* attention: strtoull, convert string to unsigned long long: as the platform of my router is 32bit*/


	return p;


}



/*
		case TCP_CONNTRACK_ESTABLISHED:
		case TCP_CONNTRACK_CLOSE_WAIT:
		case TCP_CONNTRACK_FIN_WAIT:
*/
/*return value: -1 process failed; 0 return success; 1 protocol not concered;
 * */
int process_line(struct nf_conntrack *ct, char *str) {
	const char *sep = " ";
	char *p;
	int i = 0;

	if (ct == NULL || str == NULL)
		return -1;

	memset(ct,'\0',sizeof(struct nf_conntrack));

	p = strtok(str,sep);
	if(p)
		p = process_layers(ct,p,sep);
	
	/*FIND src=*.*.*.*  */
	while(p) {

		if(strstr(p,"src") != NULL)
			break;
		//else
		p = strtok(NULL,sep);
	}

	if(p)
		p = process_orig(ct,p,sep);

	/*FIND src=*.*.*.*  */
	while(p) {

		if(strstr(p,"src") != NULL)
			break;
		//else
		p = strtok(NULL,sep);
	}
	
	if(p)
		p = process_repl(ct,p,sep);

	return 0; //success 
	

}

#define FILENAME "/proc/net/nf_conntrack"
static int nfnetlink_not_supported(int(*p_callback)(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void*data)) {
	struct nf_conntrack ct;
	char buf[512];
	FILE *f = fopen(FILENAME,"r");
	if(f==NULL)
		return -1; 
	while(1) {
		fgets(buf,1024,f);
		
		if(feof(f))
			break;
		LOG_INFO("%s",buf);
		printf("result=%d\n",process_line(&ct,buf));
		cb(0,&ct,NULL);
			
	}
	fclose(f);
	return 0;

}

#endif

int main(int argc, char *argv[]) {
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
	if(argc < 2 || inet_aton(argv[1],&gw_ip) == 0) 
		gw_ip.s_addr = 0;
	
	init();

#ifndef NFNETLINK_NOT_SUPPORTED
	h = nfct_open(CONNTRACK,0);
	//h = nfct_open(CONNTRACK,NF_NETLINK_CONNTRACK_NEW|NF_NETLINK_CONNTRACK_UPDATE);
	if(!h) {
		LOG_ERR("nfct_open");
		return -1;
	}
	/*inital buffers*/
	
	nfct_callback_register(h,NFCT_T_ALL,cb,NULL);

#endif
	/*add default rule*/
	if(rule_init() != 0 ) {
		LOG_ERR("Failed to initialize rule \n");
		conti = 0;
	}
	while(conti) {
		start = time((time_t*)NULL);
#ifndef NFNETLINK_NOT_SUPPORTED
		//LOG_DEBUG("start time=%d\n",start);
		//LOG_DEBUG("before query\n");
		ret = nfct_query(h,NFCT_Q_DUMP,&family);
		//ret = nfct_send(h,NFCT_Q_DUMP,a);//,NFCT_Q_DUMP,&family);
		//ret = nfct_catch(h);//,NFCT_Q_DUMP,&family);
		LOG_DEBUG("after query\n");
#else
		ret = nfnetlink_not_supported(cb);
		

#endif
		if (ret == -1) {
			//fprintf(stderr,"error ret==-1");
			LOG_ERR("(%d)(%s)\n",ret,strerror(errno));
			break;
		}
		else
		    LOG_DEBUG("OK;start=%d\n",start);

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
