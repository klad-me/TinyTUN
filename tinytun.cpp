#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <getopt.h>

#include "crypt.h"
#include "server.h"
#include "client.h"


void usage(void)
{
    fprintf(stderr, "Available options\n");
    fprintf(stderr, "  -k / --key KEY           Specify connection key (4..16 chars)\n");
    fprintf(stderr, "  -s / --server PORT       Run as server and listen on specified port\n");
    fprintf(stderr, "  -c / --client HOST:PORT  Run as client and connect to specified HOST:PORT\n");
    fprintf(stderr, "  -t / --timeout t         Set keepalive timeout (5..60 sec, client only)\n");
    fprintf(stderr, "  -d / --dev DEV           Use specified networking interface name\n");
    fprintf(stderr, "                               client's default is tap%%d\n");
    fprintf(stderr, "                               server's default is none (just route packets without netif)\n");
    exit(-1);
}


int main(int argc, char **argv)
{
    int server_port=0;
    char *client_host_port=0;
    const char *key_str=0;
    const char *dev=0;
    int keepalive=60;
    
    // Parsing command line options
    struct option opts[]=
    {
	{ "server",	required_argument,	0,	's' },
	{ "client",	required_argument,	0,	'c' },
	{ "key",	required_argument,	0,	'k' },
	{ "dev",	required_argument,	0,	'd' },
	{ "timeout",	required_argument,	0,	't' },
	{ 0 }
    };
    int opt;
    while ( (opt=getopt_long(argc, argv, "s:c:k:d:t:", opts, 0)) > 0)
    {
	switch (opt)
	{
	    case 's':
		server_port=atoi(optarg);
		break;
	    
	    case 'c':
		client_host_port=strdup(optarg);
		break;
	    
	    case 'k':
		key_str=strdup(optarg);
		if (strlen(key_str) < 4)
		{
		    fprintf(stderr, "Error: key must be at least 4 characters\n");
		    return -1;
		}
		
		// Hiding password for ps/top/etc
		{
		    char *s=optarg;
		    while (*s)
			(*s++)=0;
		}
		break;
	    
	    case 'd':
		dev=optarg;
		break;
	    
	    case 't':
		if ( (sscanf(optarg, "%d", &keepalive)!=1) ||
		     (keepalive < 5) ||
		     (keepalive > 60) )
		{
		    fprintf(stderr, "Error: incorrect timeout value\n");
		}
		break;
	    
	    case '?':
	    default:
		// Bad option
		usage();
	}
    }
    
    // Checking arguments
    if ( (optind < argc) ||
	 (! key_str) ||
	 ( (server_port==0) && (!client_host_port) ) ||
	 ( (server_port>0) && (client_host_port) ) )
	usage();
    
    // Seeding random
    srand(time(NULL));
    
    // Making a key from password
    makeKey128(key_str);
    
    // Starting server
    if (server_port > 0)
    {
	if (! start_server(dev, server_port)) return -1;
    }
    
    // Starting client
    if (client_host_port)
    {
	const char *host=client_host_port;
	int port=0;
	
	char *sport=strchr(client_host_port, ':');
	if ( (! *sport) || (sscanf(sport+1, "%d", &port)!=1) || (port < 1) || (port > 65535) )
	{
	    fprintf(stderr, "Error: incorrect client port\n");
	    return -1;
	}
	
	(*sport)=0;	// ':' -> nul
	
	if (! *host)
	{
	    // No host
	    fprintf(stderr, "Error: no host specified\n");
	    return -1;
	}
	
	if (! start_client(dev, host, port, keepalive)) return -1;
    }
    
    // Everything is ok
    return 0;
}
