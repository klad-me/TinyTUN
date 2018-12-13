# TinyTUN
Tiny tunneling daemon for Linux.<br/>
No external dependencies needed (except tun/tap driver in kernel).


# Encryption
Uses xtea for encryption of data. Password is shared between all nodes.


# Usage
```
Available options
  -k / --key KEY           Specify connection key (4..16 chars)
  -s / --server PORT       Run as server and listen on specified port
  -c / --client HOST:PORT  Run as client and connect to specified HOST:PORT
  -t / --timeout t         Set keepalive timeout (5..60 sec, client only)
  -d / --dev DEV           Use specified networking interface name
                               client's default is tap%d
                               server's default is none (just route packets without netif)
```
It returns network interface name to stdout (or nothing if it's just route server).

One server can handle unlimited clients. Server use MAC-tables routing (like your home router/switch does).
So all you need is to assign different IP addresses to clients. MAC is set
by tun/tap driver.


# Server
Server can run in 2 modes:

1. Server without networking interface (only routes packets):

```
    tinytun -k mypassword -s 12345
```

2. Server with networking interface:

```
    VPN=`tinytun -k mypassword -s 12345 -d 'vpn%d'`
    ifconfig $VPN 10.0.0.1
```


# Client
Client automaticly connects to server:
```
    VPN=`tinytun -k mypassword -c myserver:5000`
    ifconfig $VPN 10.0.0.2
```


# Building
Just type
```
    make
```
And you'll get tinytun binary. Place it wherever you need (for example to /usr/local/bin) and use it from rc-scripts.
