import socket, struct, argparse, fcntl
import binascii
from uuid import getnode as get_mac
from random import randint

MAX_BYTES = 65535

def getMacInBytes():
    mac = str(hex(get_mac()))
    mac = mac[2:]
    while len(mac) < 12 :
        mac = '0' + mac
    macb = b''
    for i in range(0, 12, 2) :
        m = int(mac[i:i + 2], 16)
        macb += struct.pack('!B', m)
    return macb
	
class DHCP_Discovery:
	def __init__(self):
		self.transactionID=b''
		for i in range(4):
			t=randint(0, 255)
			self.transactionID+=struct.pack('!B', t) #!: network(big-endian), B: unsigned char
			#print 'XID len: '+ len(self.transactionID)
		
		global CXID
		CXID=self.transactionID
			
	def buildPacket(self):
		packet=b''
		#print type(packet)
		packet+=b'\x01'
		#print type(packet)
		packet+=b'\x01'
		packet+=b'\x06'
		packet+=b'\x00'
		packet+=CXID #index=7(8-1), length(XID)=8
		#packet+=b'\x39\x03\xF3\x26'

		packet+=b'\x00\x00'
		packet+=b'\x00\x00'
		packet+=b'\x00\x00\x00\x00'
		packet+=b'\x00\x00\x00\x00'
		packet+=b'\x00\x00\x00\x00'
		packet+=b'\x00\x00\x00\x00'
		packet+=b'\x00\x26\x9e\x04\x1e\x9b' #clnt mac addr
		#print getMacInBytes('eth0')
		packet+= b'\x00' * 202
		packet+= b'\x63\x82\x53\x63' #Magic cookie: DHCP
		packet+= b'\x35\x01\x01' #x35=53 Option: (t=53,l=1) DHCP Message Type = DHCP Discover
		packet+= b'\x37\x04\x03\x01\x06\x0F' #DHCP option 55: Parameter Request List: Request Subnet Mask (1), Router (3), Domain Name (15), Domain Name Server (6)
		packet += b'\xff'   #End Option
		#print type(packet)
		return packet
		
class DHCP_Offer:
	def __init__(self, xid, mac):
		self.xid=xid
		self.mac=mac
	
	def OfferPkt(self):
		packet=b''
		packet+=b'\x02'
		packet+=b'\x01'
		packet+=b'\x06'
		packet+=b'\x00'
		packet+=self.xid#b'\x39\x03\xF3\x26'
		packet+=b'\x00\x00'
		packet+=b'\x00\x00'
		packet+=b'\x00\x00\x00\x00'
		packet+=b'\xC0\xA8\x01\x64'
		packet+=b'\xC0\xA8\x01\x01'
		packet+=b'\x00\x00\x00\x00'
		packet+=self.mac #b'\x00\x26\x9e\x04\x1e\x9b' #CHADDR (Client hardware address) from 245~250
		packet+= b'\x00' * 202
		packet+=b'\x63\x82\x53\x63' #magic cookie 
		packet+=b'\x35\x01\x02' #DHCP option, option=53, len=1, type=2(offer)
		packet+=b'\x01\x04\xff\xff\xff\x00' #DHCP option 1: 255.255.255.0, len=4
		packet+=b'\x03\x04\xC0\xA8\x01\x01' #DHCP option 3: 192.168.1.1 router, len=4
		packet+=b'\x33\x04\x00\x01\x51\x80' #DHCP option 51: 86400s (1 day) IP address lease time
		packet+=b'\x36\x04\x8C\x7B\x68\xBC' #DHCP option 54: 140.123.104.188 DHCP server
		packet+=b'\x06\x04\x09\x07\x0A\x0F' #DHCP option 6: DNS servers 9.7.10.15
		packet += b'\xff'   #End Option
		
		return packet
		

class DHCP_Request:
		
	def ReqPkt(self):
		packet=b''
		packet+=b'\x01'
		packet+=b'\x01'
		packet+=b'\x06'
		packet+=b'\x00'
		packet+=CXID #b'\x39\x03\xF3\x26'
		packet+=b'\x00\x00'
		packet+=b'\x00\x00'
		packet+=b'\x00\x00\x00\x00'
		packet+=b'\x00\x00\x00\x00'
		packet+=b'\xC0\xA8\x01\x01' ################# server ip 192.168.1.1
		packet+=b'\x00\x00\x00\x00'
		packet+=GetMacAddr('eth0')#b'\x00\x26\x9e\x04\x1e\x9b' # clnt mac
		packet+=b'\x00' * 202
		packet+=b'\x63\x82\x53\x63' #magic cookie
		packet+=b'\x35\x01\x03' #DHCP option, option=53, len=1, type=3(REQ)
		packet+=b'\x32\x04\xC0\xA8\x01\x64'	#DHCP option 50: 192.168.1.100 requested
		packet+=b'\x36\x04\x8C\x7B\x68\xBC' #DHCP option 54: 140.123.104.188 DHCP server
		packet+=b'\xff'   #End Option
		
		return packet
		
class DHCP_Ack:
	def __init__(self, xid, mac):
		self.xid=xid
		self.mac=mac
		
	def AckPkt(self):
		packet=b''
		packet+=b'\x02'
		packet+=b'\x01'
		packet+=b'\x06'
		packet+=b'\x00'
		packet+=XID #b'\x39\x03\xF3\x26'
		packet+=b'\x00\x00'
		packet+=b'\x00\x00'
		packet+=b'\x00\x00\x00\x00'
		packet+=b'\xC0\xA8\x01\x64'
		packet+=b'\xC0\xA8\x01\x01'
		packet+=b'\x00\x00\x00\x00'
		packet+=self.mac#b'\x00\x26\x9e\x04\x1e\x9b' #CHADDR (Client hardware address) from 245~250
		packet+= b'\x00' * 202
		packet+=b'\x63\x82\x53\x63' #magic cookie
		packet+=b'\x35\x01\x05' #DHCP option, option=53, len=1, type=5(ack)
		packet+=b'\x01\x04\xff\xff\xff\x00' #DHCP option 1: 255.255.255.0, len=4
		packet+=b'\x03\x04\xC0\xA8\x01\x01' #DHCP option 3: 192.168.1.1 router, len=4
		packet+=b'\x33\x04\x00\x01\x51\x80' #DHCP option 51: 86400s (1 day) IP address lease time
		packet+=b'\x36\x04\x8C\x7B\x68\xBC' #DHCP option 54: 140.123.104.188 DHCP server
		packet+=b'\x06\x04\x09\x07\x0A\x0F' #DHCP option 6: DNS servers 9.7.10.15
		
		return packet
	
def judgeDHCPpkt(pkt):
	#find magic cookie
	global macook #magic cookie index
	macook=pkt.find(b'\x63\x82\x53\x63') #x63:236 x82:237 
	#print('x06: %d ',pkt.find(b'\x06')) #  =2
	#print ('macook=%d', macook)
	if macook!=-1:
		#find option, discover: 53
		#get transactionID
		global XID
		global MAC
		XID=pkt[4:8]
		#print str.decode(XID)
		#print 'XID posi: ', pkt.find('\x39\x03\xF3\x26') #XID
		MAC=pkt[28:34]
		#print 'MAC posi: ', pkt.find(b'\x00\x26\x9e\x04\x1e\x9b')
		
		#print 'MAC:'
		#print type(MAC)

		if pkt.find(b'\x35\x01\x01', macook)!=-1:
			#it's a DHCP_Discovery pkt
			print ('do_nothing')
			return 1
		elif pkt.find(b'\x35\x01\x02', macook)!=-1:
			#it's a DHCP_OFFER pkt
			return 2
		elif pkt.find(b'\x35\x01\x03', macook)!=-1:
			#it's a DHCP_request pkt
			return 3
		elif pkt.find(b'\x35\x01\x05', macook)!=-1:
			#it's a DHCP_ack pkt
			return 5
		else:
			return 6

def client(hostname):
	#broadcast DHCP discovery
	sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.bind(('0.0.0.0', 68))
	print ('client bind OK')
	DD=DHCP_Discovery()
	
	sock.sendto(DD.buildPacket(), ('255.255.255.255', 67)) #140.123.104.188 255.255.255.255
	print('DHCP Discover sent waiting for reply...\n')
	
	while True:
		print ('in while, Client waits for Offer Packet')
		off_pkt=sock.recv(MAX_BYTES)
		if (judgeDHCPpkt(off_pkt)==2) and (off_pkt[4:8]==CXID): #offer packet
			print ('clnt get offer packet')
			Req=DHCP_Request()
			sock.sendto(Req.ReqPkt(), ('255.255.255.255', 67)) #140.123.104.188 255.255.255.255
			print ('client send REQ packet')
			break
		else:
			print ('ERROR, client expect offer packet')	
	
	pkt=b''
	while True:
		print ('in while, Client waits for Ack Packet')
		pkt=sock.recv(MAX_BYTES)
		if (judgeDHCPpkt(pkt)==5) and (pkt[4:8]==CXID):
			print ('Client gets a ACK packet')
			break
		else:
			print ('error pkt')
			
	
	print ('Work Done, close socket')
	sock.close()
	
	#handle packet, get info:
	#1, find mask:
	tmpNum=pkt.find(b'\x01\x04', 240) #magic:236, +4=240
	mask=pkt[tmpNum+2: tmpNum+6] #+1:because len=1, 
	
	tmpNum=pkt.find(b'\x03\x04', 240) #option=3, router len=4
	router=pkt[tmpNum+2: tmpNum+6]
	
	tmpNum=pkt.find(b'\x06\x04', 240) #option=3, router len=4
	dns=pkt[tmpNum+2: tmpNum+6]
	
	
	print ('Now, print the configuration from server:')
	#print config:
	print ('IP: 192.168.1.1')
	print ('Subnet mask: '), struct.unpack("4B", mask) #type(mask)=str, but content is bytes
	print ('Router: '), struct.unpack("4B", router)
	print ('DNS server:'), struct.unpack("4B", dns)
	
def server(interface):
	sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.bind((interface, 67))
	print ('bind 192.168.1.1 OK')
	
	while True: #get discover pkt
		print ('in while, waitting for Discover Packet')
		disc_pkt=sock.recv(MAX_BYTES)
		print ('serv get a pkt')
		caseNum=judgeDHCPpkt(disc_pkt)
		if caseNum==1:
			#handle offer pkt
			offPkt=DHCP_Offer(XID, MAC)
			sock.sendto(offPkt.OfferPkt(), ('255.255.255.255', 68))
			print ('server send offer packet')
			break
		else:
			print ('server got other packet(require DHCP discover Packet)')
	
	
	while True: #to get req Pkt            
		print ('in while, waitting for Reguest Packet')
		req_pkt=sock.recv(MAX_BYTES)
		print ('server get a packet')
		if (judgeDHCPpkt(req_pkt)==3) and (XID==req_pkt[4:8]):
			#handle Ack packet
			ackPkt=DHCP_Ack(XID, MAC)
			sock.sendto(ackPkt.AckPkt(), ('255.255.255.255', 68))
			print ('server send Ack packet')
			break
		else:
			print ('Error packet, expect Request Packet')
			
	print ('Work Done, close socket')
	sock.close()

if __name__=='__main__':
	choices={'client': client, 'server':server}
	parser=argparse.ArgumentParser(description='Send and receiver UDP locally')
	parser.add_argument('role', choices=choices, help='which role to play')
	parser.add_argument('host', help='interface the server listens at;'
                        ' host the client sends to')
	#parser.add_argument('-p', metavar='PORT', type=int, default=1060, help='UDP port (default 1060)')
	args=parser.parse_args()
	function=choices[args.role]
	#function=(args.p)
	function(args.host)
	
	
