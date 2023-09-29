import threading
from scapy.all import IPv6, IP, TCP, Ether, sniff

# we will use threading to run multiple functions at the same time 
# and thus not lose any packet while processing the data
# we will use Scapy python library for network analysis (capture and analyze TCP packets in real-time)

# Batoul's part
# function to sniff and format data
def packetsniffer():
    while True:
        #capture TCP packets indefinitely and without storing internally
        packet = sniff(filter="tcp", prn=packet_extract, store=False) 
        # by specifying the packet_extract function as the callback function (prn), it will be called for each packet that is captured

# we will define another function to extract information from the packet 
def packet_extract(packet):
    try: 
        #created dictionary to store packet information 
        packet_info = {
             "srcIp": packet[IP].src,
             #will get a string representing the IP address
             "dstIp" : packet[IP].dst,
             "ackNb" : packet[TCP].ack,
             #will get an integer representing the ack nunmber
             "flags": packet[TCP].flags,
             #will get an integer represeting each flag:
             #ACK -> 16 (binary: 010000)
             #PSH -> 8 (binary: 001000)
             #RST -> 4 (binary 000100)
             #SYN -> 2 (binary: 000010)
             #FIN -> 1 (binary:000001)
                                     
             "seqNb" : packet[TCP].seq,
             #will get an integer representing the seq number
             "srcPort": packet[TCP].sport,
             #will get an integer representing the port number
             "dstPort": packet[TCP].dport,
             "srcMac": packet[Ether].src,
             #will get a string representing the MAC address
             "dstMac": packet[Ether].dst,
             "time": packet.time,
             #will get a float representing the time in seconds since the epoch
                     
        }
    except IndexError:
        "srcIp": packet[IPv6].src
        "destIp": packet[IPv6].dst

        #add packet_info to the sharedData list
        sharedData.append(packet_info)



# Bechara's part
# function to detect the attack
# in this function I will take data that was added to the sharedData list by Batoul's function
# and use it to study the connections opened with the server to detect the attack
# add more explanation later on
def detectAttack(sharedData):
    # i will use an index to keep track of where i am in the list in case the list gets updated while i'm processing data
    index=0
    local=[]
    while True:
        if len(sharedData) > index:
            # in this if condition i check if there is new data in the list for me to use 

            #if there is i will take it and save it to variable local to my thread
            local=sharedData[index]
            # we could then in order to save storage set the data in the list to None so that we know that this data was already processed
            #sharedData[index] = None

            # we increment the index so that we can check when new data is added to the list
            index += 1
        
        if local != []:
            # here i will process the data using the the local variable


            # after i'm done processing the data i will set the local variable to an empty list
            # so that i don't process the same data again
            local=[]

            


# this list will be used so the two threads can share data between them
sharedData = []

# creating the threads
thread1 = threading.Thread(target=packetsniffer)
thread2 = threading.Thread(target=detectAttack, args=(sharedData,))

# starting the threads
# thread1.start()
# thread2.start()
