import json
import socket
from collections import Counter
from datetime import datetime
import os
import time

SERVER_IP = '54.71.128.194'
SERVER_PORT = 8808
LISTEN_PORT = 16458
END_MSG = "900#BYE"
FILE_DETAILS = 'SIZE={size},HTML={html}' 
UPLOAD_CODE = "700#" 

all_packets = {'IPS':{},'Countries': {},'Dports':{},'Programs':{},'Incomings':{},'Outgoings':{},'Alerts':{}}
data_to_upload = {'%%TIMESTAMP%%': '',
				'%%AGENTS_IN_KEYS%%':[],
				'%%AGENTS_IN_VALUES%%':[],
				'%%AGENTS_OUT_KEYS%%':[],
				'%%AGENTS_OUT_VALUES%%':[],
				'%%COUNTRIES_KEYS%%':[],
				'%%COUNTRIES_VALUES%%':[],
				'%%IPS_KEYS%%':[],
				'%%IPS_VALUES%%':[],
				'%%APPS_KEYS%%':[],
				'%%APPS_VALUES%%':[],
				'%%PORTS_KEYS%%':[],
				'%%PORTS_VALUES%%':[],
				'%%ALERTS%%':[]}

def read_temp_file():
	"""
	read from the file the the setting data and prase the the data
	Input:none
	Output:Informed information
	"""
	with open("./template/html/template.html") as file: 
		data = file.read() 
	file.close()
	return data

def prase_data_file(data):
	"""
	prase data and make
	Input:data
	Output:prase data
	"""
	for key in data_to_upload.keys():
		data = data.replace(key, str(data_to_upload[key]))
	return(data)

def write_temp_file(data):
	"""
	write the data to file
	Input:data
	Output:none
	"""
	file = open("./template/html/my_file.html","w")
	file.write(data) 
	file.close()

def read_settings_file():
	"""
	read from the file the the setting data and prase the the data
	Input:none
	Output:Informed information
	"""
	setting_dict = {}
	with open("settings.dat") as file: 
		data = file.read() 
	file.close()
	data = data.split("\n")
	for set in data:
		set = set.split(" = ")
		setting_dict[set[0]] = (set[1]).split(",")
	for key in setting_dict.keys():
		temp_dict = {} 
		for set in setting_dict[key]:
			set = set.split(":")
			temp_dict[set[1]] = set[0]
		setting_dict[key] = temp_dict
	return setting_dict

def open_sock_UDP():
	"""
	open UDP socket
	Input:none
	Output:Details of the socket
	"""
	soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	server_address = ('127.0.0.1',LISTEN_PORT)
	soc.bind(server_address)
	return soc

def send_msg_UDP(soc,client_addr, msg):
	"""
	send UDP msg to the client
	Input:Details of the socket and details of the client and the msg
	Output:none
	"""
	soc.sendto(msg.encode(), client_addr)

def get_msg_UDP(soc):
	"""
	get UDP msg from the client
	Input:Details of the socket
	Output:client msg and details of the client
	"""
	client_msg, client_addr = soc.recvfrom(8192)
	temp = [client_msg.decode(), client_addr]
	return temp

def connection_TCP():	
	"""
	This function open TCP sock conversation
	Input: none
	Output:server socket
	"""
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_address = (SERVER_IP, SERVER_PORT)
	sock.connect(server_address)
	return sock

def send_msg_TCP(soc, msg):
	"""
	This function send message from the client to server
	Input: socket information and the message to send
	Output:none
	"""
	soc.sendall(msg.encode())

def prase_first_msg(first, last):
	"""
	This make first msg to send to server upload
	Input: first name and last name
	Output:the msg to send
	"""
	start_msg = "400#USER=f.l"
	start_msg = start_msg.replace("f", first)
	start_msg = start_msg.replace("l", last)
	return start_msg

def prase_file_msg():
	"""
	This function make of file to send upload server
	Input: none
	Output: the msg
	"""
	with open("./template/html/my_file.html") as file: 
		data = file.read() 
	file.close()
	to_send = UPLOAD_CODE + FILE_DETAILS.format(size=len(data), html=data)
	return to_send

def get_ans_TCP(soc):
	"""
	This function get message from the server
	Input: socket information
	Output:the ans from server
	"""
	msg = soc.recv(1024)
	return msg.decode()

def prase_data_of_msg(msg, name, ip, black_list):
	"""
	prase the data received from the agent
	Input:msg form agent and name of the worker his ip and black list
	Output:none
	"""
	msg = (msg.split("@"))
	msg = (msg[1]).split("*")
	for packet in msg[1:]:
		packet = json.loads(packet)
		size = packet['Bytes']
		if packet['Ip'] in all_packets['IPS']:
			(all_packets['IPS'])[packet['Ip']] += size
		else:
			(all_packets['IPS'])[packet['Ip']] = size
		if not (("private range" and "private range" ) == packet['Country']):
			if packet['Country'] in all_packets['Countries']:
				(all_packets['Countries'])[packet['Country']] += size
			else:
				(all_packets['Countries'])[packet['Country']] = size
		if packet['Dport'] in all_packets['Dports']:
			(all_packets['Dports'])[packet['Dport']] += size
		else:
			(all_packets['Dports'])[packet['Dport']] = size
		if packet['Program'] in all_packets['Programs']:
			(all_packets['Programs'])[packet['Program']] += size
		else:
			(all_packets['Programs'])[packet['Program']] = size
		if packet['Incoming']:
			if name in all_packets['Incomings']:
				(all_packets['Incomings'])[name] += size
			else:
				(all_packets['Incomings'])[name] = size
		else:
			if name in all_packets['Outgoings']:
				(all_packets['Outgoings'])[name] += size
			else:
				(all_packets['Outgoings'])[name] = size
		if packet['Ip'] in black_list.values():
			if not name in all_packets['Alerts']:
				temp_tupple = (name, ip)
				all_packets['Alerts'].temp_tupple

def give_five_common(the_dict):
	"""
	give the five common in the dict
	Input:dict
	Output:dict with the five coomon
	"""
	temp = {}
	list1 = Counter(the_dict)
	list1 = list1.most_common(5)
	for parm in list1:
		temp[parm[0]] = parm[1]
	return temp

def make_data_to_upload(workers):
	"""
	prase the dict of the  data to upload
	Input:workers dict
	Output:none
	"""
	data_to_upload['%%TIMESTAMP%%'] = datetime.now().strftime('%d.%m.%Y %H:%M')
	all_ips = give_five_common(all_packets['IPS'])
	data_to_upload['%%IPS_KEYS%%'] = list(all_ips.keys())
	data_to_upload['%%IPS_VALUES%%'] = list(all_ips.values())
	all_countries = give_five_common(all_packets['Countries'])
	data_to_upload['%%COUNTRIES_KEYS%%'] = list(all_countries.keys())
	data_to_upload['%%COUNTRIES_VALUES%%'] = list(all_countries.values())
	all_ports = give_five_common(all_packets['Dports'])
	data_to_upload['%%PORTS_KEYS%%'] = list(all_ports.keys())
	data_to_upload['%%PORTS_VALUES%%'] = list(all_ports.values())
	all_apps = give_five_common(all_packets['Programs'])
	data_to_upload['%%APPS_KEYS%%'] = list(all_apps.keys())
	data_to_upload['%%APPS_VALUES%%'] = list(all_apps.values())
	all_incomings = give_five_common(all_packets['Incomings'])
	data_to_upload['%%AGENTS_IN_KEYS%%'] = list(all_incomings.keys())
	data_to_upload['%%AGENTS_IN_VALUES%%'] = list(all_incomings.values())
	all_outgoings = give_five_common(all_packets['Outgoings'])
	data_to_upload['%%AGENTS_OUT_KEYS%%'] = list(all_outgoings.keys())
	data_to_upload['%%AGENTS_OUT_VALUES%%'] = list(all_outgoings.values())
	data_to_upload['%%ALERTS%%'] = all_packets['Alerts']

def upload_file_to_internet(first_name, last_name):
	"""
	upload file to internet
	Input:first name and last name
	Output:none
	"""
	start_msg = prase_first_msg(first_name, last_name)
	msg = str(prase_file_msg())
	input("press to continue.....")
	soc_srv = connection_TCP()
	send_msg_TCP(soc_srv, start_msg)
	print(get_ans_TCP(soc_srv))
	send_msg_TCP(soc_srv, msg)
	print(get_ans_TCP(soc_srv))
	send_msg_TCP(soc_srv, END_MSG)
	print(get_ans_TCP(soc_srv))
	soc_srv.close()

def check_if_got_packets_of_all_workers(list1, list2):
	#check if the list is equal
	return (list1.sort() == list2.sort())

def main():
	print("Hello boss!!!")
	boss_first_name = input("Enter your first name:")
	boss_last_name = input("Enter your last name:")
	sock = open_sock_UDP()
	setting = read_settings_file()
	workers = setting['WORKERS']
	black_list = setting['BLACKLIST']
	ans = True
	round = 0
	while(ans):
		try:
			round = round + 1
			print("round: ",round)
			names_round = []
			ans1 = True
			while (ans1):
				temp = get_msg_UDP(sock)
				client_msg = temp[0]
				client_addr = temp[1]
				try:
					name = workers[client_addr[0]]
					if not name in names_round:
						names_round.append(name)
						prase_data_of_msg(client_msg, name, client_addr[0], black_list)
					if(check_if_got_packets_of_all_workers(names_round, list(workers.values()))):
						ans1= False
				except:
					pass
				make_data_to_upload(workers)
				write_temp_file(prase_data_file(read_temp_file()))
				upload_file_to_internet(boss_first_name, boss_last_name)
		except:
			ans = False
	print("Good bye!!!")
	sock.close()

if __name__ == "__main__": 
    main() 