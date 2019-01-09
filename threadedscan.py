import sys
import threading
from queue import Queue
from socket import *
from datetime import datetime
import subprocess

#subprocess.call('clear', shell=True)
print_lock = threading.Lock()
def header(start, target):
	tgtIP = gethostbyname(target)
	tgtName = gethostbyaddr(tgtIP)
	print("=" * 60)
	print('[+]Scan Results for: ' + tgtName[0])
	print('[+]IP: ' + tgtIP)
	print('Scanning started At: ' + str(start))
	print('    Port        Status')
	print("=" * 60)

def portscan(port):
	s = socket(AF_INET, SOCK_STREAM)
	try:
		con = s.connect((target,port))
		with print_lock:
			print('[+] %d/tcp 	OPEN' % port)
			print('-' * 60)
			con.close()
	except:
		pass



def threader():
	while True:
		worker = q.get()
		portscan(worker)
		q.task_done()

q = Queue()

def footer(end, start):
	total = end - start
	print("=" * 60)
	print("Scan finished at: ", str(end))
	print("Scan finished in: ", str(total))
	print("=" * 60)

def main():
	start = datetime.now()
	header(start,target)

	for x in range(1000):
		t = threading.Thread(target=threader)
		t.daemon = True
		t.start()

	for worker in range(1,65535):
		q.put(worker)

	q.join()
	end = datetime.now()
	footer(end, start)


if __name__ == "__main__":
	target = input("Enter IP or host to scan: ")
	main()