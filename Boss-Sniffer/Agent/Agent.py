import socket
import json
import requests
from scapy3k.all import *
import datetime
import re
import subprocess
import ctypes, sys
import _thread

SERVER_ADDR = '127.0.0.1'
SERVER_PORT = 16458
TIME_OUT = 300
MAX_PACKET = 50
URL = "http://ip-api.com/csv/"
privet = "private range"
United_States = "United States"
ip_country_dict = {}
my_ip_now = socket.gethostbyname_ex(socket.gethostname())[-1]
prog = {}

def is_admin():
	#check if the window open as admin
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def give_pograms():
	"""
	this function give the programs work at the computer and prase in dict
	Input:none
	Output:none
	"""
	if is_admin():
		while True:
			process = subprocess.Popen(['netstat','-nb'],stdout=subprocess.PIPE).communicate()
			process = (process[0]).decode()
			pattern = "([0-9]+.[0-9]+.[0-9]+.[0-9]+):[0-9]+ +.[A-Za-z].+\n .([A-Za-z]+.exe)"#ip_dst
			matches = re.findall(pattern, process)
			for tup in matches:
				if not '127.0.0.1' in tup:
					if not tup[0] in prog.keys():
						prog[tup[0]] = tup[1]
	else:
		# Re-run the program with admin rights
		ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)

def aplication_filter(packet):
	"""
	filter function to snif check if have app layer in packet
	Input:packet
	Output:True or False
	"""
	return IP in packet and (UDP in packet or TCP in packet) 

def sniffer():
	"""
	function do snif 
	Input:none
	Output:the sniffed packets
	"""
	packets = sniff(count=MAX_PACKET, lfilter=aplication_filter, timeout=TIME_OUT)
	return packets

def found_country(ip_check):
	"""
	function check the country of the ip 
	Input:ip to check
	Output:the name of the country
	"""
	new_url = URL + str(ip_check)
	response = requests.get(new_url)
	html = response.text
	html = html.split(",")
	html = str(html[1])
	if "private range" in html:
		return privet
	elif "United States" in html:
		return United_States
	return html

def prase_data_of_packet(packet):
	"""
	function prase data of one packet in tuple
	Input:ip of user and  packet
	Output:tuple of packet data
	"""
	ipS = str(packet[IP].src)
	ipD = str(packet[IP].dst)
	size = int(packet[IP].len)
	if (ipS in my_ip_now):
		ip_join = ipD
		port_join = int(packet.sport)
		incoming_ans = False
	else:
		ip_join = ipS
		port_join = int(packet.dport)
		incoming_ans = True
	temp_tuple = (ip_join, port_join, incoming_ans, size)
	if not ip_join in ip_country_dict.keys():
		ip_country_dict[ip_join] = found_country(ip_join)
	return temp_tuple

def prase_data_packets(packets):
	"""
	function prase data of all packets in dict
	Input:ip of user and  packets
	Output:prase data
	"""
	all_packets = ""
	for packet in packets:
		packet_dict = {}
		tuple_data = prase_data_of_packet(packet)
		packet_dict['Ip']= tuple_data[0]
		packet_dict['Country']= ip_country_dict[tuple_data[0]]
		packet_dict['Incoming']= tuple_data[2]
		packet_dict['Dport']= tuple_data[1]
		packet_dict['Bytes']= tuple_data[3]
		if tuple_data[0] in prog:
			packet_dict['Program']= prog[tuple_data[0]]
		else:
			packet_dict['Program']= "Unknown"
		all_packets += '*'+json.dumps(packet_dict)
	return(all_packets)

def make_msg(data):
	"""
	function make the msg to send 
	Input:data
	Output:the msg
	"""
	msg = str(len(data)) + '@' + str(data)
	return msg

def open_sock():
	"""
	open UDP socket
	Input:none
	Output:Details of the socket
	"""
	soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return soc

def send_msg(soc, msg):
	"""
	send UDP msg from the server
	Input:Details of the socket and the msg
	Output:none
	"""
	server_address = (SERVER_ADDR, SERVER_PORT)
	soc.sendto(msg.encode(),server_address)

def get_msg(soc):
	"""
	get UDP msg from the server
	Input:Details of the socket
	Output:server msg 
	"""
	server_msg, server_addr = soc.recvfrom(1024)
	return server_msg.decode()

def main():
	ans = True
	sock = open_sock()
	_thread.start_new_thread(give_pograms, ())
	while(ans):
		try:
			print("start snif...")
			packets = sniffer()
			print("stop sniff")
			data = prase_data_packets(packets)
			print("send msg")
			send_msg(sock,make_msg(data))
		except:
			ans = False
	print("Good bye!!!")	
	sock.close()
if __name__ == "__main__": 
    main() 