import sys
import select
import os
import struct
import socket
import argparse
import time
import timeit

HOPS = 30
TTL = 1

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

def iphdr(domain,opt):
	version = 4
	headlength = 5
	tos = 0
	totallength = 0
	id = 0
	flag = 0
	offset = 0
	ttl = TTL
	if opt =='udp':
		protocol = 17
	elif opt =='icmp':
		protocol = 1
	checksum = 0
	#0.0.0.0
	src = 0x0a00020f
	#127.0.0.1
	dst = socket.inet_aton(socket.gethostbyname(domain))
	print(socket.gethostbyname(domain))
	ipheader = struct.pack("!BBHHHBBHL", ((version & 0xff) <<4) + (headlength & 0xff),tos,totallength,id,((flag & 0xffff) << 13) + (offset & 0x1fff),ttl,protocol,checksum,src)+dst
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
	print(UDPheader)
	return UDPheader



def ICMP_ping(domain, rtime = 1):
	with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)as sniffe_sock:
		#sniffe_sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
		with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)as receive_sock:
			#               HOPS
			for j in range(0,10):
				global TTL
				A = [0,0,0]
				packet = iphdr(domain,'icmp') + icmphdr()
				
				for i in range(0,3):
					sniffe_sock.sendto(packet,(domain,0))
					start = timeit.default_timer()

					result, address = receive_sock.recvfrom(1024)
					stop = timeit.default_timer()
	
					delay = stop - start
					delay = delay * 1000
					A[i] = delay

				if A[0]>3 or A[1]>3 or A[2]>3:
					print ("%d  :   *     *     *   fail" %TTL)
				elif result[20] == 11 and result[21] == 0 :
					print ("%d  :   %0.2fms    %0.2fms    %0.2fms     %s  " %(TTL,A[0],A[1],A[2],address))
				elif result[20] == 0 and result[21] == 0 :
					#same : ICMP id,ICMP data 
					print ("%d  :   %0.2fms    %0.2fms    %0.2fms     %s  " %(TTL,A[0],A[1],A[2],address))
					break
				TTL = TTL+1

def UDP_ping(domain, rtime = 1):
	with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)as sniffe_sock:
		#sniffe_sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)

		with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)as receive_sock:
			for j in range(0,10):
				global TTL
				A = [0,0,0]
				packet = iphdr(domain,'udp') + UDPhdr()
				for i in range(0,3):
					sniffe_sock.sendto(packet,(domain,0))
					start = timeit.default_timer()

					result, address = receive_sock.recvfrom(1024)
					stop = timeit.default_timer()
	
					delay = stop - start
					delay = delay * 1000
					A[i] = delay

				if A[0]>3 or A[1]>3 or A[2]>3:
					print ("%d  :   *     *     *   fail" %TTL)
				elif result[20] == 11 and result[21] == 0 :
					print ("%d  :   %0.2fms    %0.2fms    %0.2fms     %s  " %(TTL,A[0],A[1],A[2],address))
				elif result[20] == 3 and result[21] == 3 :
					#same : IP id,UDP dst port
					print ("%d  :   %0.2fms    %0.2fms    %0.2fms     %s  " %(TTL,A[0],A[1],A[2],address))
					break

				TTL = TTL+1

			#who are you..------
			i=struct.calcsize("d")
			time=struct.unpack("d",result[28:28 + i])[0]
			#-------------------
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

#python3 final.py -d google.com -U



