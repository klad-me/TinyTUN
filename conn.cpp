#include "conn.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "crypt.h"
#include "debug.h"


// Maximum packet size
#define MAX_PKT_SIZE	1600	// eth frame + headers

// Maximum queue size
#define MAX_Q_SIZE	131072


int Conn::mac_table_size=8;


Conn::Conn(int _sock, pktHandler _handler, int keepalive)
{
    DEBUG("Conn: open\n");
    
    sock=_sock;
    handler=_handler;
    if (keepalive==0)
    {
	// Server
	keepalive_period=60;
	keepalive_timeout=90;
	keepalive_answer=true;
    } else
    {
	// Client
	keepalive_period=keepalive;
	keepalive_timeout=keepalive + keepalive/2;	// 1.5x for timeout
	keepalive_answer=false;
    }
    
    fin=false;
    
    rd.state=0;
    rd.buf=0;
    
    wr.pos=0;
    
    outq=0;
    outq_tail=&outq;
    outq_size=0;
    
    // Write key
    rand128(writeKey);	// making seed
    sendRaw(writeKey, 16);	// sending it to peer
    encrypt128(writeKey, key128);	// making write key
    
    // No read key for now
    readKey=0;
    
    // Empty MAC table
    mac_table=0;
    
    // Setting timeouts
    timeout_t=time(NULL) + keepalive_timeout;
    keepalive_t=time(NULL) + keepalive_period;
    
    // Setting TCP no-delay (speeds up traffic 2x times)
    int value = 1;
    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&value, sizeof(value)))
    {
	DEBUG("Warning: can't set TCP_NODELAY option\n");
    }
}


Conn::~Conn()
{
    DEBUG("Conn: closed\n");
    
    if (!fin) close(sock);
    
    if (rd.buf) delete[] rd.buf;
    
    while (outq)
    {
	delete[] outq->buf;
	struct outq *n=outq->next;
	delete outq;
	outq=n;
    }
    
    if (readKey) delete[] readKey;
    
    if (mac_table) delete[] mac_table;
}


bool Conn::needRead()
{
    return true;
}


void Conn::doRead()
{
    uint8_t buf[1024];
    
    // Reading all available data in the socket
    while (1)
    {
        int len=read(sock, buf, sizeof(buf));
	if (len<=0)
	{
	    if ( (len==0) || (errno != EAGAIN) )
	    {
		// Closed or error
		fin=true;
		close(sock);
	    }
	    return;
	}
	DEBUG("Conn: read %d\n", len);
	
	// Splitting data to packets
	uint8_t *data=buf;
	while (len > 0)
	{
	    switch (rd.state)
	    {
		case 0:
		    // Length-low
		    rd.len=(*data++);
		    rd.state++;
		    len--;
		    break;
		
		case 1:
		    // Length-high
		    rd.len|=(*data++) << 8;
		    rd.state++;
		    len--;
		    if ( (rd.len > MAX_PKT_SIZE) ||
			 ((rd.buf=new uint8_t[rd.len])==NULL) )
		    {
			// Bad packet size or buffer allocation failed
			DEBUG("Conn: bad packet size\n");
			fin=true;
			close(sock);
			return;
		    }
		    rd.pos=0;
		    break;
		
		case 2:
		    // Reading packet data
		    {
			int l=rd.len-rd.pos;
			if (l > len) l=len;
			memcpy(rd.buf+rd.pos, data, l);
			data+=l;
			len-=l;
			rd.pos+=l;
			if (rd.pos >= rd.len)
			{
			    // Got packet
			    DEBUG("Conn: recv packet size=%d\n", rd.len);
			    if (! handlePkt())
			    {
				// Bad packet
				DEBUG("Conn: bad packet\n");
				fin=true;
				close(sock);
				return;
			    }
			    
			    // Restarting receiption
			    delete[] rd.buf;
			    rd.buf=0;
			    rd.pos=0;
			    rd.state=0;
			}
		    }
		    break;
	    }
	}
    }
}


bool Conn::needWrite()
{
    if ( (! outq) && (time(NULL) > keepalive_t) )
    {
	// Time to send keepalive
	sendRaw(0, 0);	// empty packet
    }
    
    return outq != 0;
}


void Conn::doWrite()
{
    while (outq != 0)
    {
	int len=write(sock, outq->buf+wr.pos, outq->len-wr.pos);
	if (len<=0)
	{
	    if ( (len==0) || (errno != EAGAIN) )
	    {
		// Closed or error
		fin=true;
		close(sock);
	    }
	    return;
	}
	DEBUG("Conn: write %d\n", len);
	
	wr.pos+=len;
	if (wr.pos >= outq->len)
	{
	    // Packet finished
	    wr.pos=0;
	    outq_size-=outq->len;
	    delete[] outq->buf;
	    struct outq *n=outq->next;
	    delete outq;
	    outq=n;
	    
	    // If no more packets - pointing tail to outq
	    if (! outq) outq_tail=&outq;
	}
    }
}


bool Conn::needClose()
{
    return fin || (time(NULL) > timeout_t);
}


bool Conn::handlePkt()
{
    // Updating keepalive timeout
    timeout_t=time(NULL)+keepalive_timeout;
    
    // Checking for key
    if (! readKey)
    {
	// First packet must be read key
	
	// Checking key length
	if (rd.len != 16)
	{
	    DEBUG("Conn: incorrect key length %d\n", rd.len);
	    return false;
	}
	
	// Making read key
	readKey=new uint8_t[16];
	if (! readKey) return false;
	memcpy(readKey, rd.buf, 16);
	encrypt128(readKey, key128);
	
	// Checking that readKey != writeKey
	if (memcmp(readKey, writeKey, 16)==0) return false;
	
	// Key is ok
	DEBUG("Conn: got readKey\n");
	return true;
    }
    
    if (rd.len==0)
    {
	// It's a keepalive packet
	DEBUG("Conn: got keepalive\n");
	return true;
    }
    
    // Checking packet length (must be aligned by 16 bytes)
    if ((rd.len & 15) != 0)
    {
	DEBUG("Conn: bad packet length %d\n", rd.len);
	return false;
    }
    
    // Decrypting packet
    uint16_t offs=0;
    while (offs < rd.len)
    {
	decrypt128(rd.buf+offs, readKey);
	offs+=16;
    }
    
    // Checking length
    uint16_t len=rd.buf[0] | (rd.buf[1] << 8);
    if (len+4 > rd.len)
    {
	DEBUG("Conn: bad decrypted length %d\n", len);
	return false;
    }
    
    // Checking CRC
    if (crc16(0xffff, rd.buf, len+4) != 0x0000)
    {
	DEBUG("Conn: bad decrypted CRC\n");
	return false;
    }
    
    // Remembering src MAC in MAC table
    addMAC(rd.buf+2+6);
    
    // Starting handler
    DEBUG("Conn: got packet size=%d\n", len);
    return handler(this, rd.buf+2, len);
}


bool Conn::sendRaw(const uint8_t *data, uint16_t len)
{
    // Checking maximum queue size
    if (outq_size+len+2 > MAX_Q_SIZE) return false;
    
    // Creating queue element
    struct outq *q=new struct outq;
    if (! q) return false;
    q->buf=new uint8_t[len+2];	// 2 bytes for length
    if (! q->buf)
    {
	// Allocation failed
	delete q;
	return false;
    }
    q->buf[0]=len & 0xff;	// length-low
    q->buf[1]=len >> 8;		// length-high
    if (len > 0) memcpy(q->buf+2, data, len);
    q->len=len+2;
    q->next=0;
    outq_size+=len+2;
    
    // Adding to outq
    (*outq_tail)=q;
    
    // Switching outq_tail
    outq_tail=&(q->next);
    
    // Updating keepalive period
    keepalive_t=time(NULL) + keepalive_period;
    
    DEBUG("Conn: sent raw packet size=%d\n", len);
    return true;
}


bool Conn::send(const uint8_t *data, uint16_t len)
{
    // Calculating size for size+pkt+crc aligned by 16 bytes
    uint16_t sz=(len+2+2+15) & ~15;	// 2 bytes - size, 2 bytes - crc16
    
    // Checking maximum queue size
    if (outq_size+sz+2 > MAX_Q_SIZE) return false;
    
    // Creating queue element
    struct outq *q=new struct outq;
    if (! q) return false;
    q->buf=new uint8_t[sz+2];	// 2 bytes for raw length
    if (! q->buf)
    {
	// Allication failed
	delete q;
	return false;
    }
    q->len=sz+2;
    q->next=0;
    outq_size+=sz+1;
    
    // Generating packet
    q->buf[0]=sz & 0xff;	// raw-length-low
    q->buf[1]=sz >> 8;		// raw-length-high
    q->buf[2]=len & 0xff;	// length-low
    q->buf[3]=len >> 8;		// length-high
    memcpy(q->buf+4, data, len);
    uint16_t crc=crc16(0xffff, q->buf+2, len+2);	// calculating crc for packet
    q->buf[4+len+0]=crc & 0xff;	// crc-low
    q->buf[4+len+1]=crc >> 8;	// crc-high
    
    // Encryping packet
    uint16_t offs=0;
    while (offs < sz)
    {
	encrypt128(q->buf+2+offs, writeKey);
	offs+=16;
    }
    
    // Adding to outq
    (*outq_tail)=q;
    
    // Switching outq_tail;
    outq_tail=&(q->next);
    
    // Updating keepalive period
    keepalive_t=time(NULL) + keepalive_period;
    
    DEBUG("Conn: sent encrypted packet size=%d\n", len);
    return true;
}


void Conn::addMAC(const uint8_t *mac)
{
    uint16_t min_use=0xffff;
    uint8_t min_n=0;
    bool found=false, div=false;
    
    // Creating MAC table
    if (! mac_table)
    {
	mac_table=new struct mac_table[mac_table_size];
	if (! mac_table) return;
    }
    
    // Looking for MAC in table
    for (uint8_t i=0; i<mac_table_size; i++)
    {
	if ( (mac_table[i].use > 0) &&
	     (memcmp(mac_table[i].mac, mac, 6)==0) )
	{
	    // Found
	    found=true;
	    if (mac_table[i].use < 0xffff)
		mac_table[i].use++; else
		div=true;
	    break;
	}
	
	if (mac_table[i].use < min_use)
	{
	    // Remembering least used item
	    min_use=mac_table[i].use;
	    min_n=i;
	}
    }
    
    // Checking for division
    if (div)
    {
	// Should div all use counters by 2
	for (uint8_t i=0; i<mac_table_size; i++)
	    mac_table[i].use>>=1;
    }
    
    // Checking if MAC was found
    if (found) return;
    
    // Adding MAC to first free slot
    memcpy(mac_table[min_n].mac, mac, 6);
    mac_table[min_n].use=1;
}


bool Conn::findMAC(const uint8_t *mac)
{
    // Checking if mac_table exist
    if (! mac_table) return false;
    
    // Looking for MAC in table
    for (uint8_t i=0; i<mac_table_size; i++)
    {
	if ( (mac_table[i].use > 0) &&
	     (memcmp(mac_table[i].mac, mac, 6)==0) )
	{
	    // Found
	    return true;
	}
    }
    
    // Not found
    return false;
}
