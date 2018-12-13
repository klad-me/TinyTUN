#include "tap.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_tun.h>


#ifdef EBUG
    #define DEBUG(...)	printf(__VA_ARGS__)
#else
    #define DEBUG(...)	do{}while(0)
#endif


int tap_fd=-1;


const char* tap_open(const char *dev)
{
    // Default interface name
    if (! dev) dev="tap%d";
    
    // Opening tun/tap device
    if ( (tap_fd=open("/dev/net/tun", O_RDWR)) < 0 )
    {
	// Failed
	perror("/dev/net/tun");
        return 0;
    }
    
    // Getting TAP
    static struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP;    // with Ethernet headers
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(tap_fd, TUNSETIFF, (void*)&ifr) < 0)
    {
        fprintf(stderr, "Error: can't get TAP interface\n");
        close(tap_fd);
        return 0;
    }
    
    // Setting non-blocking mode
    fcntl(tap_fd, F_SETFL, O_NONBLOCK);
    
    
    // Returning TAP name
    return ifr.ifr_name;
}
