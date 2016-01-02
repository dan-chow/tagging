/*util for store and lookup
 * functions for insert rules into iptables
 * 
*/
/*1.table:mangle table,
 *2.chain: POSTROUTING
 *3.target:-j DSCP
 *4.action: --set-dscp
 *5.default:tcp
 * */
#include <assert.h>
#include <memory.h>
#include <sys/errno.h>

#include "log.h"
#include "iptc.h"
#include <linux/netfilter/xt_DSCP.h> /*for DSCP info*/

#define FIRST_FOR_EF  0 
#define INSERT_FIRST 1 //0 is for 0x2e
#define DELETE_FIRST 1

#define SIZE_IPT_ENTRY            (IPT_ALIGN(sizeof(struct ipt_entry)))
#define SIZE_IPT_ENTRY_MATCH      (IPT_ALIGN(sizeof(struct ipt_entry_match)))
#define SIZE_IPT_ENTRY_TARGET	  (IPT_ALIGN(sizeof(struct ipt_entry_target)))
#define SIZE_IPT_TCP	          (IPT_ALIGN(sizeof(struct ipt_tcp)))
#define SIZE_IPT_DSCP_INFO	  (IPT_ALIGN(sizeof(struct xt_DSCP_info)))

#define TOTAL_SIZE (SIZE_IPT_ENTRY + SIZE_IPT_ENTRY_MATCH + SIZE_IPT_ENTRY_TARGET + SIZE_IPT_TCP + SIZE_IPT_DSCP_INFO)

/*For simplicity, inserting default rule separeates from insert_rule.....*/
int rule_init() {
#define MAXLEN 512

	char buf[MAXLEN];
	struct iptc_handle *handle;
	int ret = 1;
	uint32_t src = 0;
	uint32_t dst = 0;

        struct ipt_entry *entry;
	struct ipt_entry_match *match_proto; /*proto and l4port*/
	struct ipt_entry_target *target;
	//struct ipt_tcp *tcpinfo;
	struct xt_DSCP_info *dscp_info; 
	
	uint32_t size_ipt_entry, size_ipt_entry_match, size_ipt_entry_target,size_ipt_dscp_info;
	size_ipt_entry = SIZE_IPT_ENTRY;//IPT_ALIGN(sizeof(struct ipt_entry));
	size_ipt_entry_match = SIZE_IPT_ENTRY_MATCH;//IPT_ALIGN(sizeof(struct ipt_entry_match));
	size_ipt_entry_target = SIZE_IPT_ENTRY_TARGET;//IPT_ALIGN(sizeof(struct ipt_entry_target));
	//size_ipt_tcp = IPT_ALIGN(sizeof(struct ipt_tcp));
	size_ipt_dscp_info = SIZE_IPT_DSCP_INFO;//IPT_ALIGN(sizeof(struct xt_DSCP_info));

	uint32_t total_size = size_ipt_entry + size_ipt_entry_target + size_ipt_dscp_info;
	assert(total_size < MAXLEN);
	

	memset(buf,'\0',sizeof(buf));

	/*entry*/
	entry = (struct ipt_entry*)buf;
	
	entry->target_offset = size_ipt_entry ;
	entry->next_offset = total_size;
	/*IPv4 address*/
	entry->ip.src.s_addr = src; /*default, mask all*/
	entry->ip.smsk.s_addr = 0x0; 

	entry->ip.dst.s_addr = dst;
	entry->ip.dmsk.s_addr = 0x0; 
	
	entry->ip.proto = IPPROTO_TCP;

	/*match proto*/
	//match_proto = (struct ipt_entry_match*) entry->elems;
	
	//match_proto->u.match_size = size_ipt_entry_match;
	//strcpy(match_proto->u.user.name,"tcp");

	/*tcp port, attention the order of bytes*/
	//tcpinfo = (struct ipt_tcp*)match_proto->data;

	//tcpinfo->spts[0] = ntohs(l4src);
	//tcpinfo->spts[1] = ntohs(l4src);
	//tcpinfo->dpts[0] = ntohs(l4dst);
	//tcpinfo->dpts[1] = ntohs(l4dst);

	/*target*/
	target = (struct ipt_entry_target*)(entry->elems);
	
	target->u.target_size = size_ipt_entry_target + size_ipt_dscp_info;
	strcpy(target->u.user.name, "DSCP");
	
	dscp_info = (struct xt_DSCP_info*) target->data;

	dscp_info->dscp = 46; //magic number:DSCP_EF
	
	
	handle = iptc_init("mangle");
	if(!handle) {
		LOG_ERR("rule_init(ERR):failed to invoke iptc_init");
		return -1;
	}

	ret = iptc_insert_entry("POSTROUTING",entry,FIRST_FOR_EF,handle);
	//ret = iptc_append_entry("POSTROUTING",entry,handle);
	if(!ret) {
		LOG_ERR("rule_init(ERR): insert a rule, %s\n",iptc_strerror(errno));
		return -1;
	}

	ret = iptc_commit(handle);

	if(!ret) {
		LOG_ERR("rule_init(ERR): Commit, %s\n",iptc_strerror(errno));
		return -1;
	}

	return 0;


}
int remove_default_rule() {
#define MAXLEN 512

	char buf[MAXLEN];
	struct iptc_handle *handle;
	int ret = 1;
	uint32_t src = 0;
	uint32_t dst = 0;

        struct ipt_entry *entry;
	struct ipt_entry_match *match_proto; /*proto and l4port*/
	struct ipt_entry_target *target;
	//struct ipt_tcp *tcpinfo;
	struct xt_DSCP_info *dscp_info; 
	
	uint32_t size_ipt_entry, size_ipt_entry_match, size_ipt_entry_target,size_ipt_dscp_info;
	size_ipt_entry = SIZE_IPT_ENTRY;//IPT_ALIGN(sizeof(struct ipt_entry));
	size_ipt_entry_match = SIZE_IPT_ENTRY_MATCH;//IPT_ALIGN(sizeof(struct ipt_entry_match));
	size_ipt_entry_target = SIZE_IPT_ENTRY_TARGET;//IPT_ALIGN(sizeof(struct ipt_entry_target));
	//size_ipt_tcp = IPT_ALIGN(sizeof(struct ipt_tcp));
	size_ipt_dscp_info = SIZE_IPT_DSCP_INFO;//IPT_ALIGN(sizeof(struct xt_DSCP_info));

	uint32_t total_size = size_ipt_entry + size_ipt_entry_target + size_ipt_dscp_info;
	assert(total_size < MAXLEN);
	

	memset(buf,'\0',sizeof(buf));

	/*entry*/
	entry = (struct ipt_entry*)buf;
	
	entry->target_offset = size_ipt_entry ;
	entry->next_offset = total_size;
	/*IPv4 address*/
	entry->ip.src.s_addr = src; /*default, mask all*/
	entry->ip.smsk.s_addr = 0x0; 

	entry->ip.dst.s_addr = dst;
	entry->ip.dmsk.s_addr = 0x0; 
	
	entry->ip.proto = IPPROTO_TCP;

	/*match proto*/
	//match_proto = (struct ipt_entry_match*) entry->elems;
	
	//match_proto->u.match_size = size_ipt_entry_match;
	//strcpy(match_proto->u.user.name,"tcp");

	/*tcp port, attention the order of bytes*/
	//tcpinfo = (struct ipt_tcp*)match_proto->data;

	//tcpinfo->spts[0] = ntohs(l4src);
	//tcpinfo->spts[1] = ntohs(l4src);
	//tcpinfo->dpts[0] = ntohs(l4dst);
	//tcpinfo->dpts[1] = ntohs(l4dst);

	/*target*/
	target = (struct ipt_entry_target*)(entry->elems);
	
	target->u.target_size = size_ipt_entry_target + size_ipt_dscp_info;
	strcpy(target->u.user.name, "DSCP");
	
	dscp_info = (struct xt_DSCP_info*) target->data;

	dscp_info->dscp = DSCP_EF; //magic number:DSCP_EF
	
	unsigned char matchmask[SIZE_IPT_ENTRY + SIZE_IPT_ENTRY_TARGET + SIZE_IPT_DSCP_INFO];

	handle = iptc_init("mangle");
	if(!handle) {
		LOG_ERR("remove_default_rule(ERR):failed to invoke iptc_init");
		return -1;
	}
	ret = iptc_delete_entry("POSTROUTING",entry,matchmask,handle);
	if(!ret) {
		LOG_ERR("remove_default_rule(ERR):",iptc_strerror(errno));
		return -1;

	}

	ret = iptc_commit(handle);

	if(!ret) {
		LOG_ERR("rule_init(ERR): Commit, %s\n",iptc_strerror(errno));
		return -1;
	}

	return 0;
}

int insert_rule(const char *table,
		const char *chain,
		struct in_addr src_addr,
		struct in_addr dst_addr,
		uint8_t dscp,
		uint8_t proto,
		uint16_t l4src,
		uint16_t l4dst,
		const char *target_name)
{
#define MAXLEN 512

	char buf[MAXLEN];
	struct iptc_handle *handle;
	int ret = 1;
	uint32_t src = src_addr.s_addr;
	uint32_t dst = dst_addr.s_addr;

        struct ipt_entry *entry;
	struct ipt_entry_match *match_proto; /*proto and l4port*/
	struct ipt_entry_target *target;
	struct ipt_tcp *tcpinfo;
	struct xt_DSCP_info *dscp_info; /*TODO: later*/
	
	uint32_t size_ipt_entry, size_ipt_entry_match, size_ipt_entry_target, size_ipt_tcp,size_ipt_dscp_info;
	size_ipt_entry = IPT_ALIGN(sizeof(struct ipt_entry));
	size_ipt_entry_match = IPT_ALIGN(sizeof(struct ipt_entry_match));
	size_ipt_entry_target = IPT_ALIGN(sizeof(struct ipt_entry_target));
	size_ipt_tcp = IPT_ALIGN(sizeof(struct ipt_tcp));
	size_ipt_dscp_info = IPT_ALIGN(sizeof(struct xt_DSCP_info));

	uint32_t total_size = size_ipt_entry + size_ipt_entry_match + size_ipt_entry_target + size_ipt_tcp + size_ipt_dscp_info;
	assert(total_size < MAXLEN);
	
	
	if(src ==0 || dst == 0 || proto == 0 || l4src == 0 || l4dst == 0)
		return -1;

	memset(buf,'\0',sizeof(buf));

	/*entry*/
	entry = (struct ipt_entry*)buf;
	
	entry->target_offset = size_ipt_entry + size_ipt_entry_match + size_ipt_tcp;
	entry->next_offset = total_size;
	/*IPv4 address*/
	entry->ip.src.s_addr = src;
	entry->ip.smsk.s_addr = 0xffffffff;

	entry->ip.dst.s_addr = dst;
	entry->ip.dmsk.s_addr = 0xffffffff;
	
	entry->ip.proto = IPPROTO_TCP;

	/*match proto*/
	match_proto = (struct ipt_entry_match*) entry->elems;
	
	match_proto->u.match_size = size_ipt_entry_match + size_ipt_tcp;
	strcpy(match_proto->u.user.name,"tcp");

	/*tcp port, attention the order of bytes*/
	tcpinfo = (struct ipt_tcp*)match_proto->data;

	tcpinfo->spts[0] = ntohs(l4src);
	tcpinfo->spts[1] = ntohs(l4src);
	tcpinfo->dpts[0] = ntohs(l4dst);
	tcpinfo->dpts[1] = ntohs(l4dst);

	/*target*/
	target = (struct ipt_entry_target*)(entry->elems + size_ipt_entry_match + size_ipt_tcp);
	
	target->u.target_size = size_ipt_entry_target + size_ipt_dscp_info;
	strcpy(target->u.user.name, "DSCP");
	
	dscp_info = (struct xt_DSCP_info*) target->data;

	dscp_info->dscp = dscp;
	
	
	handle = iptc_init(table);
	if(!handle) {
		LOG_ERR("failed to invoke iptc_init");
		return -1;
	}

	ret = iptc_insert_entry(chain,entry,INSERT_FIRST,handle);
	if(!ret) {
		LOG_ERR("Error: insert a rule, %s\n",iptc_strerror(errno));
		return -1;
	}
	//LOG_INFO("%s",target->data);

	ret = iptc_commit(handle);

	if(!ret) {
		LOG_ERR("Error: Commit, %s\n",iptc_strerror(errno));
		return -1;
	}

	return 0;
}

/*Only iptc iterate and delet according to number
 * */
int delete_rule(const char *table,
		const char *chain,
		struct in_addr src_addr,
		struct in_addr dst_addr,
		uint8_t dscp,
		uint8_t proto,
		uint16_t l4src,
		uint16_t l4dst,
		const char *target_name)
{
#define MAXLEN 512

	char buf[MAXLEN];
	struct iptc_handle *handle;
	int ret = 1;
	uint32_t src = src_addr.s_addr;
	uint32_t dst = dst_addr.s_addr;

        struct ipt_entry *entry;
	struct ipt_entry_match *match_proto; /*proto and l4port*/
	struct ipt_entry_target *target;
	struct ipt_tcp *tcpinfo;
	struct xt_DSCP_info *dscp_info; /*TODO: later*/
	

	uint32_t size_ipt_entry, size_ipt_entry_match, size_ipt_entry_target, size_ipt_tcp,size_ipt_dscp_info;
	size_ipt_entry = IPT_ALIGN(sizeof(struct ipt_entry));
	size_ipt_entry_match = IPT_ALIGN(sizeof(struct ipt_entry_match));
	size_ipt_entry_target = IPT_ALIGN(sizeof(struct ipt_entry_target));
	size_ipt_tcp = IPT_ALIGN(sizeof(struct ipt_tcp));
	size_ipt_dscp_info = IPT_ALIGN(sizeof(struct xt_DSCP_info));

	uint32_t total_size = size_ipt_entry + size_ipt_entry_match + size_ipt_entry_target + size_ipt_tcp + size_ipt_dscp_info;
	assert(total_size < MAXLEN);
	
	
	if(src ==0 || dst == 0 || proto == 0 || l4src == 0 || l4dst == 0)
		return -1;

	memset(buf,'\0',sizeof(buf));

	/*entry*/
	entry = (struct ipt_entry*)buf;
	
	entry->target_offset = size_ipt_entry + size_ipt_entry_match + size_ipt_tcp;
	entry->next_offset = total_size;
	/*IPv4 address*/
	entry->ip.src.s_addr = src;
	entry->ip.smsk.s_addr = 0xffffffff;

	entry->ip.dst.s_addr = dst;
	entry->ip.dmsk.s_addr = 0xffffffff;
	
	entry->ip.proto = IPPROTO_TCP;

	/*match proto*/
	match_proto = (struct ipt_entry_match*) entry->elems;
	
	match_proto->u.match_size = size_ipt_entry_match + size_ipt_tcp;
	strcpy(match_proto->u.user.name,"tcp");

	/*tcp port, attention the order of bytes*/
	tcpinfo = (struct ipt_tcp*)match_proto->data;

	tcpinfo->spts[0] = ntohs(l4src);
	tcpinfo->spts[1] = ntohs(l4src);
	tcpinfo->dpts[0] = ntohs(l4dst);
	tcpinfo->dpts[1] = ntohs(l4dst);

	/*target*/
	target = (struct ipt_entry_target*)(entry->elems + size_ipt_entry_match + size_ipt_tcp);
	
	target->u.target_size = size_ipt_entry_target + size_ipt_dscp_info;
	strcpy(target->u.user.name, "DSCP");
	
	dscp_info = (struct xt_DSCP_info*) target->data;

	dscp_info->dscp = dscp;
	
	unsigned char matchmask[TOTAL_SIZE]; // = (char*)malloc(entry->next_offset);
	memset(matchmask,'\0',entry->next_offset);
	
	handle = iptc_init(table);
	if(!handle) {
		LOG_ERR("failed to invoke iptc_init");
		return -1;
	}
	/*delete,It seems that matchmask is non-sense but the length is required*/
	ret = iptc_delete_entry(chain,entry,matchmask,handle);
	if(!ret) {
		LOG_ERR("failed to delete rules");
		return -1;

	}
	int i = 0;
	//for(i=0;i<entry->next_offset; ++i) {
	//		printf("%d ",(char)matchmask[i]);
	//}

	ret = iptc_commit(handle);

	if(!ret) {
		LOG_ERR("Error: Commit, %s\n",iptc_strerror(errno));
		return -1;
	}


	return 0;
}
