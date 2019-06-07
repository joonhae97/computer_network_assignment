import sys
import select
import os
import struct
import socket
import argparse


def intTobytes(n):
	result = bytearray()
	while(n):
		result.append(n&0xff)
		n=n>>8
	return result[::-1]

def chksum(str):   
   sum =0
   count =0
   countTo = (len(str)/2)*2
   #2.sum header
   while count<countTo:
      thisVal = str[count+1] *256 + str[count]
      sum = sum +thisVal
      #8bytes
      sum = sum &0xffffffff
      count = count +2
   #???
   if countTo <len(str):
      sum = sum +ord(str[lent(str)-1])
      sum = sum &0xffffffff
   #3.more than 4 bytes
   sum = (sum>>16) + (sum&0xffff)
   sum = sum + (sum>>16)
   #4.complement
   answer = ~sum
   answer = answer & 0xffff
   #Endian
   answer = answer >> 8 | (answer << 8 & 0xff00)
   return answer

#ICMP request packet
def icmphdr():
   #Echo request //reply (0)
   ICMP_ECHO =8
   code = 0
   #1.checksum reset
   checksum =0
   id = os.getpid()
   seq=1
   #64bit
   icmpheader = struct.pack("bbHHh", ICMP_ECHO, code, checksum, id, seq)
   checksum = chksum(icmpheader)
   #host to network short(2bytes) // Byte Order
   icmpheader = struct.pack("bbHHh", ICMP_ECHO, code, socket.htons(checksum), id, seq)
   return icmpheader
 
#create ip_header 

def iphdr(opt):
	print(opt)
	version = 4
	headlength = 5
	tos = 0
	totallength = 0
	id = 0
	flag = 0
	offset = 0
	ttl = 1
	if opt =='udp':
		protocol = 17
	elif opt =='icmp':
		protocol = 1
	checksum = 0
	#192.168.254.129
	src = 0x00000000
	#172.217.24.142
	dst = 0x7f000001
	ipheader = struct.pack("!BBHHHBBHLL", ((version & 0xff) <<4) + (headlength & 0xff),tos,totallength,id,((flag & 0xffff) << 13) + (offset & 0x1fff),ttl,protocol,checksum,src,dst)
	return ipheader

def UDPhdr():
	src_port =56
	dst_port =33434
	header_len = 0
	checksum = 0
	data = b'hello'
	UDPheader = struct.pack("!HHHH",src_port, dst_port, header_len, checksum)
	header_len = len(UDPheader)+len(data)
	UDPheader = struct.pack("!HHHH",src_port, dst_port, header_len, checksum)+data
	
	return UDPheader
 
def ICMP_ping(domain, rtime = 1):
	with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)as sniffe_sock:
		sniffe_sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
		packet = iphdr('icmp') + icmphdr()
		sniffe_sock.sendto(packet,(domain,0))
		with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)as receive_sock:
			result = receive_sock.recvfrom(1024)
			print(result)
		receive_sock.close()
	sniffe_sock.close()
	return result

def UDP_ping(domain, rtime = 1):
	with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)as sniffe_sock:
		sniffe_sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
		packet = iphdr('udp') + UDPhdr()
		sniffe_sock.sendto(packet,(domain,0))
		with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)as receive_sock:
			result = receive_sock.recvfrom(1024)
			print(result)
		receive_sock.close()
	sniffe_sock.close()
	return result

if __name__ == '__main__':
	opt_UDP = False
	parser = argparse.ArgumentParser(description = '-d domain or ip, if udp -U else none')
	parser.add_argument('-d', type = str, required = True, metavar = 'domain', help = 'domain')
	parser.add_argument('-U', type = str, default = 'no_udp', nargs = '?')
	args = parser.parse_args()
	
	opt_UDP = args.U
	
	if opt_UDP == 'no_udp':
		ICMP_ping(args.d)
	elif opt_UDP == None:
		UDP_ping(args.d)

