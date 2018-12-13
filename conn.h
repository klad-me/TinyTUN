#ifndef CONN_H
#define CONN_H


#include <stdint.h>
#include <time.h>


class Conn;


typedef bool (*pktHandler)(Conn *src, const uint8_t *data, uint16_t size);


class Conn
{
public:
    Conn(int _sock, pktHandler handler, int keepalive=0);
    ~Conn();
    
    bool needRead();
    void doRead();
    bool needWrite();
    void doWrite();
    bool needClose();
    
    bool handlePkt();
    bool sendRaw(const uint8_t *data, uint16_t len);
    bool send(const uint8_t *data, uint16_t len);
    
    void addMAC(const uint8_t *mac);
    bool findMAC(const uint8_t *mac);
    
    
    Conn *next;
    int sock;
    
    struct
    {
	uint8_t *buf;
	uint8_t state;
	uint16_t pos, len;
    } rd;
    
    struct
    {
	uint16_t pos;
    } wr;
    
    struct outq
    {
	uint8_t *buf;
	uint16_t len;
	
	struct outq *next;
    } *outq, **outq_tail;
    int outq_size;
    
    bool fin;
    
    pktHandler handler;
    
    uint8_t writeKey[16];
    uint8_t *readKey;
    
    struct mac_table
    {
	uint8_t mac[6];
	uint16_t use;
    } *mac_table;
    static int mac_table_size;
    
    uint8_t keepalive_period;
    uint8_t keepalive_timeout;
    bool keepalive_answer;
    time_t timeout_t, keepalive_t;
};


#endif
