import sys

import select

import os

import struct

import socket

import argparse

import time

import timeit

RECV_TIMEOUT = 3

MAX_HOPS = 30

TTL = 0

curr_addr = '10.0.2.15'

src_port = 55555

dst_port = 33434

IP_Length = 0

IP_CHKSUM = 0

#ip chksum

def ipchksum(data):

   size = len(data)

   if(size % 2) != 0:

      data = data + b'\x00'

      size=len(data)

 

   data = struct.unpack("!10H",data)

   #for error

   x = data[0]+data[1]+data[2]+data[3]+data[4]+data[5]+data[6]+data[7]+data[8]+data[9]

   chk = (x>>16)+(x&0xffff)

   chk = (chk^0xffff)

   return chk

#icmp chksum

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

    totallength = IP_Length

    #random ip

    id = 8889

    flag = 0

    offset = 0

    ttl = TTL

    if opt =='udp':

        protocol = 17

    elif opt =='icmp':

        protocol = 1

    checksum = IP_CHKSUM

    src = socket.inet_aton(curr_addr)

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

    global dst_port

    global src_port

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

            receive_sock.settimeout(RECV_TIMEOUT)

            for HOP in range(0,MAX_HOPS):

                global curr_addr

                global TTL

                global src_port

                global dst_port

                global IP_Length

                global IP_CHKSUM

                count = 0

                TTL = TTL + 1

                A = [0,0,0]

                for i in range(0,3):
                    packet = iphdr(dst, 'udp') + UDPhdr()

                    IP_Length = len(packet)

                    IP_CHKSUM = ipchksum(iphdr(dst, 'udp'))

                    packet = iphdr(dst, 'udp') + UDPhdr()    

                    src_port = src_port - 1

                    dst_port = dst_port + 1

                    sniffe_sock.sendto(packet,(domain,55555))

                    start = timeit.default_timer()

                    try:

                        result, address = receive_sock.recvfrom(1024)

                    except socket.timeout:

                        count = count + 1
                        
                        continue

                    stop = timeit.default_timer()   

                    delay = stop - start

                    delay = delay *1000

                    A[i] = delay
                

                if count == 3:

                    print ("%d :    *       *       *       fail" %TTL)
                    
                    continue
      #                                             send IP hdr == recv IP hdr

                if result[20] == 11 and result[21] == 0 : # packet[:20] == result[28:48]:

                    print ("%d  :   %0.2fms    %0.2fms    %0.2fms     %s  " %(TTL,A[0],A[1],A[2],address))

      #                                             send UDP dst == recv UDP dst       send IP id == recv IP id

                elif result[20] == 3 and result[21] == 3 : # packet[22:24] == result[50:52] and packet[4:6] == result[32:34]:

                    print ("%d  :   %0.2fms    %0.2fms    %0.2fms     %s  " %(TTL,A[0],A[1],A[2],address))

                    break

                TTL = TTL + 1

 

def icmp_ping(domain, opt):

    dst = socket.inet_aton(socket.gethostbyname(domain))

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)as sniffe_sock:

        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)as receive_sock:

            receive_sock.settimeout(RECV_TIMEOUT)

            for HOP in range(0,MAX_HOPS):

                global curr_addr

                global TTL

                global IP_Length

                global IP_CHKSUM
                
                count = 0 

                TTL = TTL + 1

                A = [0,0,0]

                packet = iphdr(dst, 'icmp') + ICMPhdr()

                IP_Length = len(packet)

                IP_CHKSUM = ipchksum(iphdr(dst, 'icmp'))

                packet = iphdr(dst, 'icmp') + ICMPhdr()

                for i in range(0,3):

                    send = sniffe_sock.sendto(packet,(domain,56))

                    start = timeit.default_timer()

                    try:

                        result, address = receive_sock.recvfrom(1024)

                    except socket.timeout:
                
                        count = count + 1

                        continue

                    stop = timeit.default_timer()

                    delay = stop - start

                    delay = delay *1000

                    A[i] = delay   
                
                if count ==3 :

                    print ("%d :   *   *   *   fail" %TTL)

                    continue
      #                                              send IPhdr == recv IPhdr
                if result[20] == 11 and result[21] == 0 : #and packet[:20] == result[28:48]:

                    print ("%d  :   %0.2fms    %0.2fms    %0.2fms     %s  " %(TTL,A[0],A[1],A[2],address))

      #                                                send icmp id == recv icmp id   send icmp data == recv icmp data

                elif result[20] == 0 and result[21] == 0 :     #packet[24:26] == result[52:54] and packet[28:] == result[56:]

                    print ("%d  :   %0.2fms    %0.2fms    %0.2fms     %s  " %(TTL,A[0],A[1],A[2],address))

                    break

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description = '-d domain')

    parser.add_argument('-d', type = str, required = True, metavar = 'domain', help = 'domain')

    parser.add_argument('-U', type = str, default = 'no_udp', nargs= '?')

    parser.add_argument('-I', type = str, default = 'no_icmp', nargs= '?')

    parser.add_argument('-T', type = int, nargs= '?')

    parser.add_argument('-c', type = int, nargs = '?')

    args = parser.parse_args()

    if args.T != None :

        RECV_TIMEOUT = args.T
    
    if args.c != None :

        MAX_HOPS = args.c
    
    if args.U == None :

        udp_ping(args.d, 'udp')

    elif args.I == None :

        icmp_ping(args.d, 'icmp')

