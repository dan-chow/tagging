#ifndef __IPTC_H_
#define __IPTC_H_
#include <libiptc/libiptc.h>
#include <stdint.h>
#include <arpa/inet.h>

/*l4src and l4dst must be network byte order
 * NOTE:
 */
int insert_rule(const char *table,
		const char *chain,
		struct in_addr src_addr,
		struct in_addr dst_addr,
		uint8_t dscp,
		uint8_t proto,
		uint16_t l4src,
		uint16_t l4dst,
		const char *target);

#define INSERT_RULE(src,dst,dscp,l4src,l4dst) insert_rule("mangle","POSTROUTING",src,dst,dscp,6,l4src,l4dst,"DSCP")



#endif
