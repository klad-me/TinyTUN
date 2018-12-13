#include "server.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h>

#include "conn.h"
#include "tap.h"
#include "debug.h"


Conn *tcp_conn=0;


static bool route(Conn *src, const uint8_t *data, uint16_t len)
{
    static const uint8_t bcast_mac[6]={0xff,0xff,0xff,0xff,0xff,0xff};
    
    // First 6 bytes of packet is dst MAC
    const uint8_t *dst=(data+0);
    
    // Checking for broadcast
    bool bcast=(memcmp(dst, bcast_mac, 6)==0);
    
    // Trying to route packet to connection with matching src MAC (if it's not a broadcast)
    if (! bcast)
    {
	// Checking all connections
	bool found=false;
	Conn *c=tcp_conn;
	while (c)
	{
	    // Routing to connection if MAC is found
	    if ( (c!=src) && (c->findMAC(dst)) )
	    {
		c->send(data, len);
		found=true;
	    }
	    
	    c=c->next;
	}
	if (found) return true;
    }
    
    // MAC not found (or it's a broadcast) - sending packet to all connections except src
    Conn *c=tcp_conn;
    while (c)
    {
	if (c!=src)
	    c->send(data, len);
	
	c=c->next;
    }
    
    if ( (src) && (tap_fd>=0) )
    {
	// Sending to TAP
	uint8_t buf[len+4];
	
	// Adding TAP header
	buf[0]=0;
	buf[1]=0;
	buf[2]=data[12];    // protocol type
	buf[3]=data[13];
	memcpy(buf+4, data, len);
	
	// Sending
	if (write(tap_fd, buf, len+4) != len+4)
	{
    	    DEBUG("TAP write failed (errno=%d)\n", errno);
	}
    }
    
    return true;
}


int start_server(const char *dev, int port)
{
    struct sockaddr_in SrvSockAddr;
    int SrvSock;
    
    // Opening TAP device
    if (dev)
    {
	dev=tap_open(dev);
	if (! dev) return -1;
    }
    
    // Creating server socket
    memset(&SrvSockAddr, 0x00, sizeof(SrvSockAddr));
    SrvSockAddr.sin_family=AF_INET;
    SrvSockAddr.sin_port=htons(port);
    SrvSockAddr.sin_addr.s_addr=INADDR_ANY;
    if ( (SrvSock=socket(AF_INET, SOCK_STREAM, 0)) < 0 )
    {
	perror("socket");
	return 0;
    }
    fcntl(SrvSock, F_SETFL, O_NONBLOCK);
    int yes=1;
    setsockopt(SrvSock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    if ( (bind(SrvSock,(struct sockaddr*)(&SrvSockAddr),sizeof(SrvSockAddr)))!=0 )
    {
	perror("bind");
	close(SrvSock);
	return 0;
    }
    if ( (listen(SrvSock, 10))!=0 )
    {
	perror("listen");
	close(SrvSock);
	return 0;
    }
    
    
    // Printing TAP name
    if (dev) printf("%s\n", dev);
    
    
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
	FD_SET(SrvSock,&fds_read);	// for new connections
	max_fd=SrvSock;
	{
	    Conn *ent=tcp_conn;
	    
	    while (ent)
	    {
		int sock=ent->sock;
		if (sock > max_fd) max_fd=sock;
		
		// Read list
		if (ent->needRead())
		    FD_SET(sock, &fds_read);
		
		// Write list
		if (ent->needWrite())
		    FD_SET(sock, &fds_write);
		
		// Exception list
		FD_SET(sock, &fds_except);
		
		// Next
		ent=ent->next;
	    }
	}
	if (tap_fd >= 0)
	{
	    FD_SET(tap_fd, &fds_read);
	    if (tap_fd > max_fd) max_fd=tap_fd;
	}
	
	
	// Waiting for events
	if (select(max_fd+1, &fds_read, &fds_write, &fds_except, &tv)<0)
	{
	    // select failed - skipping it
	    continue;
	}
	
	
	// Checking for server events
	if (FD_ISSET(SrvSock,&fds_read))
	{
	    // Got new connection
	    socklen_t z=sizeof(struct sockaddr_in);
	    struct sockaddr_in *addr;
	    int sock=accept(SrvSock,(struct sockaddr*)(&addr),&z);
	    
	    if (sock>=0)
	    {
		// Connection ok - putting it to the list
		Conn *ent=new Conn(sock, route);
		if (ent)
		{
		    // Class ok
		    ent->next=tcp_conn;
		    tcp_conn=ent;
		    
		    // Setting socket to non-blocking mode
		    fcntl(sock, F_SETFL, O_NONBLOCK);
		} else
		{
		    // Allocation failed
		    close(sock);
		}
	    }
	} //FD_ISSET(SrvSock, &fds_read)
	
	
	// Checking for connection's events
	{
	    Conn* *ent=&tcp_conn;
	    
	    while (*ent)
	    {
		int sock=(*ent)->sock;
		
		// Checking for read
		if (FD_ISSET(sock, &fds_read))
		{
		    (*ent)->doRead();
		}
		
		// Checking for write
		if (FD_ISSET(sock, &fds_write))
		{
		    (*ent)->doWrite();
		}
		
		// Checking for error or close
		if ( (FD_ISSET(sock, &fds_except)) ||
		     ((*ent)->needClose()) )
		{
		    // Closing connection & deleting Conn
		    Conn *tmp=(*ent);
		    (*ent)=(*ent)->next;
		    
		    delete tmp;
		    
		    continue;
		}
		
		// Next
		ent=&( (*ent)->next );
	    }
	}
	
	
	// Checking for TAP events
	if ( (tap_fd>=0) && (FD_ISSET(tap_fd, &fds_read)) )
	{
            // Packet from TAP
            uint8_t buf[1600];
            int len=read(tap_fd, buf, sizeof(buf));
            if (len > (4+14))       // TAP header + Ethernet header
            {
                // Sending to peers
                route(0, buf+4, len-4);   // removing TAP header
            } else
            {
                DEBUG("Error reading from TAP (errno=%d)\n", errno);
            }
	}
    }
}
