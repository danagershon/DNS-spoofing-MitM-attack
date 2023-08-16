# DNS-spoofing-MitM-attack
Network Security Course Spring 2023 HW3: DNS spoofing MitM attack example

• Simulating a DNS spoofing attack on a client
• Attacker sends a spoofed DNS response to the client containing the IP address of the attacker
• Attacker acts as a Man in the Middle: reads, modifies, and forwards packets between the client and the server without them knowing
• Attacker steals the client's username and password by listening to the client logging in

**files:**

• attacker.py:
attacker sniffs to catch the client's DNS request in order to create and send a spoofed DNS response. Then the attacker becomes MitM and listens to the client's credentials

Module: Python Scapy. 

• client.py: client driver program

• dnsServer.py: DNS server driver program

• httpServer.py: HTTP server driver program

• fileToDowload: text file the client downloads from the server
