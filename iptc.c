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
	uint32_t dst = src_addr.s_addr;

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

	ret = iptc_insert_entry(chain,entry,0,handle);
	if(!ret) {
		LOG_ERR("Error: insert a rule, %s\n",iptc_strerror(errno));
		return -1;
	}
	LOG_INFO("%s",target->data);

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
		uint32_t src,
		uint32_t dst,
		uint8_t proto,
		uint16_t l4src,
		uint16_t l4dst,
		const char *target)
{
	return 0;
}
