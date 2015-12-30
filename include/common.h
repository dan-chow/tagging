#ifndef __COMMON_H_
#define __COMMON_H_
#include <time.h>

struct Flow {
	uint32_t src;
	uint32_t dst;
	uint32_t l4src;
	uint32_t l4dst;
	uint32_t proto;
	uint64_t bytes; //single directs
};

struct Node {
	/*hash info:such as hhead*/
	struct Flow flow;
	time_t recent; //the recent time for modification
};


#endif
