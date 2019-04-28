## client.py

import socket
import argparse

def run(host, port):
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.connect((host, port))
		line = input(':')
		REV = rev(line)
		print(line)
		s.sendall(REV.encode())

def rev(string):
	result = string[::-1]
	return result

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="Echo client -p port -i host")
	parser.add_argument('-p', help="port_number", required=True)
	parser.add_argument('-i', help="host_name", required=True)

	args = parser.parse_args()
	run(host=args.i, port=int(args.p))
