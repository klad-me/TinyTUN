#include "client.h"

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
#include <netdb.h>
#include <signal.h>

#include "conn.h"
#include "tap.h"
#include "debug.h"


#define MAX_PACKET_SIZE	(1536+4)


bool writeTap(Conn *src, const uint8_t *data, uint16_t size)
{
    uint8_t buf[size+4];
    
    // Adding TAP header
    buf[0]=0;
    buf[1]=0;
    buf[2]=data[12];	// protocol type
    buf[3]=data[13];
    memcpy(buf+4, data, size);
    
    // Sending
    if (write(tap_fd, buf, size+4) != size+4)
    {
	DEBUG("TAP write failed (errno=%d)\n", errno);
	return false;
    }
    
    return true;
}


int start_client(const char *dev, const char *host, int port, int keepalive)
{
    // Opening TAP
    dev=tap_open(dev);
    if (! dev) return 0;
    
    // Printing TAP name
    printf("%s\n", dev);
    
    
#ifndef EBUG
    // Becoming a daemon
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    if (fork() != 0) return 1;
    
    // Setting sid, closing stdin, stdout, stderr and chdir to /
    setsid();
    close(0);
    close(1);
    close(2);
    chdir("/");
    
    // Signals to ignore
    signal(SIGHUP, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
#endif
    
    
    // Main work cycle
    while (1)
    {
	struct sockaddr_in addr;
	struct hostent *hp;
	int sock;
	uint8_t buf[MAX_PACKET_SIZE];
	
	
	// Waiting 1 sec between tries
	sleep(1);
	
	DEBUG("Connecting to %s:%d...\n", host,port);
	
	// Resolving host name
	if ( (hp=gethostbyname(host)) == 0 )
	{
	    DEBUG("Unable to resolve '%s'\n", host);
    	    continue;
	}
	
	// Creating socket
	if ((sock=socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
	    DEBUG("Socket error\n");
	    continue;
	}
	
	// Connecting
	bzero(&addr, sizeof(addr));
	bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
	addr.sin_family=hp->h_addrtype;
	addr.sin_port=htons(port);
	
	if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1)
	{
	    DEBUG("Unable to connect to '%s'\n", host);
	    continue;
	}
	
	// Setting non-blocking mode
	fcntl(sock, F_SETFL, O_NONBLOCK);
	
	// Flushing TAP packets
	while (read(tap_fd, buf, sizeof(buf)) > 0);
	
	// Creating connection class
	Conn *conn=new Conn(sock, writeTap, keepalive);
	
	// Connection loop
	while (1)
	{
	    fd_set fds_read;
	    fd_set fds_write;
	    fd_set fds_except;
	    struct timeval tv;
	    int max_fd;
	    
	    // Waiting 1sec for incoming events
	    tv.tv_sec=1;
	    tv.tv_usec=0;
	    
	    // Creating lists
	    FD_ZERO(&fds_read);
	    FD_ZERO(&fds_write);
	    FD_ZERO(&fds_except);
	    
	    FD_SET(tap_fd, &fds_read);
	    
	    if (conn->needRead()) FD_SET(sock, &fds_read);
	    if (conn->needWrite()) FD_SET(sock, &fds_write);
	    FD_SET(sock, &fds_except);
	    
	    max_fd=(sock > tap_fd) ? sock : tap_fd;
	    
	    // Waiting for events
	    if (select(max_fd+1, &fds_read, &fds_write, &fds_except, &tv)<0)
	    {
		// select failed - skipping it
		continue;
	    }
	    
	    // Checking for TAP
	    if (FD_ISSET(tap_fd, &fds_read))
	    {
		// Packet from TAP
		int len=read(tap_fd, buf, sizeof(buf));
		if (len > (4+14))	// TAP header + Ethernet header
		{
		    // Sending to server
		    conn->send(buf+4, len-4);	// removing TAP header
		} else
		{
		    DEBUG("Error reading from TAP (errno=%d)\n", errno);
		}
	    }
	    
	    // Checking for server connection
	    if (FD_ISSET(sock, &fds_read)) conn->doRead();
	    if (FD_ISSET(sock, &fds_write)) conn->doWrite();
	    if ( (FD_ISSET(sock, &fds_except)) || (conn->needClose()) )
	    {
		// Connection closed
		delete conn;
		DEBUG("Server connection closed\n");
		break;
	    }
	}
    }
}
