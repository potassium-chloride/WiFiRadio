import socket,os
from select import select

#Создано путём обратной разработки библиотеки scapy

MTU=65535
ETH_P_ALL=3

def _flush_fd(fd):
    if hasattr(fd, 'fileno'):
        fd = fd.fileno()
    while True:
        r,w,e = select([fd],[],[],0)
        if r:
            os.read(fd,MTU)
        else:
            break

def raw(x):
	try:
		return bytes(x)
	except TypeError:
		return bytes(x, encoding="utf8")

#def socket
sock=None
def init_send_iface(iface):
	global sock
	sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
	sock.bind((iface, ETH_P_ALL))
	_flush_fd(sock)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**30)#Is it really need?
	print("Сокет проинициализирован")

def sendp(sentPak,iface,count):
	global sock
#	sock.close()
#	init_send_iface(iface)
	if not type(sentPak)==bytes:
		sentPak=raw(sentPak)
	while(count>0):
		try:
			sock.send(sentPak)
		except socket.error as msg:
			if msg[0] == 22 and len(sentPak)<60:
				padding=b"\x00"*(60-len(sentPak))
				sock.send(sentPak+padding)
		count=count-1

'''
>>> raw(RadioTap()/Dot11(type=2,subtype=0,addr1="ff:ff:ff:ff:ff:ff")/"HELLO")
b'\x00\x00\x08\x00\x00\x00\x00\x00\x08\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00HELLO'
>>> raw(RadioTap()/Dot11(type=2,subtype=0,addr2="ff:ff:ff:ff:ff:ff")/"HELLO")
b'\x00\x00\x08\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00HELLO'
>>> raw(RadioTap()/Dot11(type=2,subtype=0,addr3="ff:ff:ff:ff:ff:ff")/"HELLO")
b'\x00\x00\x08\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x00HELLO'
>>> raw(RadioTap()/Dot11(type=2,subtype=0,addr1="ab:cd:ef:ab:cd:ef")/"HELLO")
b'\x00\x00\x08\x00\x00\x00\x00\x00\x08\x00\x00\x00\xab\xcd\xef\xab\xcd\xef\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00HELLO'
'''

def simpleSend(text,iface,count):
	bs=text.encode("UTF-8")
	preamb=b'\x00\x00\x08\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	sendp(preamb+bs,iface,count)

def simpleSendBytes(bs,iface,count):
	preamb=b'\x00\x00\x08\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	sendp(preamb+bs,iface,count)

def sniff(iface,prn):
	sock2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
	sock2.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
	sock2.bind((iface, ETH_P_ALL))
	_flush_fd(sock2)
	sock2.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
	sock2.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**30)#Is it really need?
	pkt=None
	sa_ll=None
	while True:
		try:
			pkt,sa_ll=sock2.recvfrom(MTU)
			if sa_ll[2] == socket.PACKET_OUTGOING:
				continue
			prn(pkt)
		except KeyboardInterrupt:
			break
