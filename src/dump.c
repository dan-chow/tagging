#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include "log.h"
#include "common.h"
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>
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

const int interval = 5000; //every five seconds
int conti = 1;

void sig_term(int signo) {
	if(signo == SIGTERM || signo == SIGINT) {
		conti = 0;
		return ;
	}
}

#define TCP_PROTO 6
#define LEVEL_1   (1024*1024)  //1MB
#define LEVEL_2   (20*1024*1024)

static int cb(enum nf_conntrack_msg_type type,
		struct nf_conntrack *ct,
		void *data
	    ) {
	char buf[1024];
	LOG_DEBUG("begin in cb\n");
	uint8_t proto = get_l4proto(ct);
	uint8_t state = get_tcp_state(ct);
	/*only attention to established TCP connections*/
	if(proto != TCP_PROTO)
	 return NFCT_CB_CONTINUE;

	switch(state) {
		case TCP_CONNTRACK_ESTABLISHED:
			break;
		default:
			return NFCT_CB_CONTINUE;
			break;
	};
	
	LOG_DEBUG("established tcp connections got!!\n");

	struct in_addr orig_src = {.s_addr = get_orig_ipv4_src(ct)};
	struct in_addr orig_dst = {.s_addr = get_orig_ipv4_dst(ct)};
	uint16_t orig_l4src = ntohs(get_orig_l4src(ct));
	uint16_t orig_l4dst = ntohs(get_orig_l4dst(ct));
	uint64_t orig_bytes = get_orig_bytes(ct);
	
	struct in_addr repl_src = {.s_addr = get_repl_ipv4_src(ct)};
	struct in_addr repl_dst = {.s_addr = get_repl_ipv4_dst(ct)};
	uint16_t repl_l4src = ntohs(get_repl_l4src(ct));
	uint16_t repl_l4dst = ntohs(get_repl_l4dst(ct));
	uint64_t repl_bytes = get_repl_bytes(ct);
	LOG_DEBUG("got neccessary data\n");
	
	struct Flow orig_flow  = {
		.src = orig_src,
		.dst = orig_dst,
		.proto = proto,
		.l4src = orig_l4src,
		.l4dst = orig_l4dst,
	};
	struct HashNode *prev = lookup_flow(&orig_flow);

	printf_flow(&orig_flow);

	

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
	while(conti) {
		start = time((time_t*)NULL);
		LOG_DEBUG("start time=%d\n",start);
		ret = nfct_query(h,NFCT_Q_DUMP,&family);
		//ret = nfct_send(h,NFCT_Q_DUMP,a);//,NFCT_Q_DUMP,&family);
		//ret = nfct_catch(h);//,NFCT_Q_DUMP,&family);

		if (ret == -1) {
			fprintf(stderr,"error ret==-1");
			LOG_ERR("(%d)(%s)\n",ret,strerror(errno));
			break;
		}
		else
		    LOG_DEBUG("OK\n");

		/*here, store, lookup and modify rules
		 * */
		now = time((time_t*)NULL);
		LOG_DEBUG("now time=%d\n",now);
		sleep((interval+start-now)/1000);

		
	}
	/*
	 * nfct_filter_detach(nfct_fd(h));
	 * nfct_filter_destroy(filter);
	 */

	//sleep(5);
	nfct_close(h);
	//ret = -1 ? exit(EXIT_FAILURE): exit(EXIT_SUCCESS);
	return 0;
}
