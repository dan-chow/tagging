#ifndef __LOG_H_
#define __LOG_H_

#include <stdio.h>
#define CRITICAL 50
#define ERROR 40
#define WARN 30
#define INFO 20
#define DEBUG 10

#define LOG_LEVEL DEBUG

/*LOG:debug*/
#if LOG_LEVEL <= DEBUG
#define LOG_DEBUG(format,...) fprintf(stdout,format,##__VA_ARGS__)
#else
#define LOG_DEBUG(format,...) 
#endif

/*LOG:info*/
#if LOG_LEVEL <= INFO
#define LOG_INFO(format,...) fprintf(stdout,format,##__VA_ARGS__)
#else
#define LOG_INFO(format,...)
#endif

/*LOG:error*/
#if LOG_LEVEL <= ERROR
#define LOG_ERR(format,args...) fprintf(stderr,format,##args)
#else
#define LOG_ERR(format,...) 
#endif



#endif
