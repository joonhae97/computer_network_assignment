import sys
import select
import os
import struct
import socket
import argparse
import time
import timeit
RECV_TIMEOUT = 50
MAX_HOPS = 30
TTL = 1
curr_addr = '10.0.2.15'
_dst_port = 33434
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

#create ip_header 

def iphdr(_dst,opt):
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
    src = socket.inet_aton('10.0.2.15')
    #127.0.0.1
    dst = _dst
    ipheader = struct.pack("!BBHHHBBH", ((version & 0xff) <<4) + (headlength & 0xff),tos,totallength,id,((flag & 0xffff) << 13) + (offset & 0x1fff),ttl,protocol,checksum)+src+dst
    return ipheader

#ICMP request packet

def ICMPhdr():

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

def UDPhdr():
    src_port =55555
    global _dst_port
    dst_port = _dst_port
    header_len = 0
    checksum = 0
    data = b''
    UDPheader = struct.pack("!HHHH",src_port, dst_port, header_len, checksum)
    header_len = len(UDPheader)+len(data)
    UDPheader = struct.pack("!HHHH",src_port, dst_port, header_len, checksum)+data
    return UDPheader

def udp_ping(domain, opt):
    dst = socket.inet_aton(socket.gethostbyname(domain))
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)as sniffe_sock:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)as receive_sock:
            receive_sock.settimeout(2)
            for HOP in range(0,300):
                global curr_addr
                global TTL
                global _dst_port
                dst_port = _dst_port
                A = [0,0,0]
                packet = iphdr(dst, 'udp') + UDPhdr()
                result = ''
                address=''
                for i in range(0,3):
                    sniffe_sock.sendto(packet,(domain,55555))
                    start = timeit.default_timer()
                    try:
                        result, address = receive_sock.recvfrom(1024)
                    except socket.timeout:
                        continue
                    stop = timeit.default_timer()	
                    delay = stop - start
                    delay = delay *1000
                    A[i] = delay
                if A[0] > RECV_TIMEOUT or A[1] > RECV_TIMEOUT or A[2] > RECV_TIMEOUT :
                    print ("%d :    *       *       *       fail" %TTL)
                elif result[20] == 11 and result[21] == 0 :
                    print ("%d  :   %0.2fms    %0.2fms    %0.2fms     %s  " %(TTL,A[0],A[1],A[2],address))
                elif result[20] == 3 and result[21] == 3:
                    print ("%d  :   %0.2fms    %0.2fms    %0.2fms     %s  " %(TTL,A[0],A[1],A[2],address))
                    break
                TTL = TTL + 1

def icmp_ping(domain, opt):
    dst = socket.inet_aton(socket.gethostbyname(domain))
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)as sniffe_sock:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)as receive_sock:
            receive_sock.settimeout(1)
            for HOP in range(0,300):
                global curr_addr
                global TTL
                global _dst_port
                dst_port = _dst_port
                A = [0,0,0]
                packet = iphdr(dst, 'icmp') + ICMPhdr()
                for i in range(0,3):
                    send = sniffe_sock.sendto(packet,(domain,56))
                    start = timeit.default_timer()
                    try:
                        result, address = receive_sock.recvfrom(1024)
                    except socket.timeout:
                        continue
                    stop = timeit.default_timer()
                    delay = stop - start
                    delay = delay *1000
                    A[i] = delay
                if A[0] > RECV_TIMEOUT or A[1] > RECV_TIMEOUT or A[2] > RECV_TIMEOUT :
                    print ("%d :	*	*	*	fail" %TTL)
                elif result[20] == 11 and result[21] == 0 :
                    print ("%d  :   %0.2fms    %0.2fms    %0.2fms     %s  " %(TTL,A[0],A[1],A[2],address))
                elif result[20] == 0 and result[21] == 0 :
                    print ("%d  :   %0.2fms    %0.2fms    %0.2fms     %s  " %(TTL,A[0],A[1],A[2],address))
                    break
                TTL = TTL + 1
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = '-d domain')
    parser.add_argument('-d', type = str, required = True, metavar = 'domain', help = 'domain')
    parser.add_argument('-U', type = str, default = 'no_udp', nargs= '?')
    parser.add_argument('-I', type = str, default = 'no_icmp', nargs= '?')
    args = parser.parse_args()
    if args.U == None :
        udp_ping(args.d, 'udp')
    elif args.I == None :
        icmp_ping(args.d, 'icmp')
