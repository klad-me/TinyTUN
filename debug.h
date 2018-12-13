#ifndef DEBUG_H
#define DEBUG_H


#include <stdio.h>


#ifdef EBUG
    #define DEBUG(...)	printf(__VA_ARGS__)
#else
    #define DEBUG(...)	do{}while(0)
#endif


#endif
