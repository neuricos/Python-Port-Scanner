#!/usr/bin/env python3

import argparse
from socket import *
from threading import *

screenLock = Semaphore(value=1)

def connScan(tgtHost, tgtPort):
	try:
		connSkt = socket(AF_INET, SOCK_STREAM)
		connSkt.connect((tgtHost, tgtPort))
		screenLock.acquire()
		print("[+]%d/tcp open" % tgtPort)
	except:
		screenLock.acquire()
		print("[-]%d/tcp closed" % tgtPort)
	finally:
		screenLock.release()
		connSkt.close()

def portScan(tgtHost, tgtPorts):
	try:
		tgtIP = gethostbyname(tgtHost)
	except:
		print("[-] Cannot resolve '%s': Unknown host" % tgtHost)
		return
	try:
		tgtName = gethostbyaddr(tgtIP)
		print("\n[+] Scan Results for: " + tgtName[0])
	except:
		print("\n[+] Scan Results for: " + tgtIP)

	setdefaulttimeout(1)

	for tgtPort in tgtPorts:
		t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
		t.start()

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-H', dest='tgtHost', required=True, type=str, help="specify target host")
	parser.add_argument('-p', nargs='+', dest='tgtPort', required=True, type=str, help="specify target port[s]")

	args = parser.parse_args()

	tgtHost = args.tgtHost
	tgtPorts = [int(p) for p in args.tgtPort]

	portScan(tgtHost, tgtPorts)

if __name__ == '__main__':
	main()
