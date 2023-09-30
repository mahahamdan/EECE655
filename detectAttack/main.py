import threading
# pip install thread6
from scapy.all import IPv6, IP, TCP, Ether, sniff, get_if_addr, conf, get_if_hwaddr
# pip install scapy

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
        srcIp=packet[IP].src
        dstIp=packet[IP].dst
    except IndexError:
        srcIp=packet[IPv6].src
        dstIp=packet[IPv6].dst
    #created dictionary to store packet information 
    packet_info = {
        "srcIp": srcIp,
         #will get a string representing the IP address
         "dstIp" : dstIp,
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
    # i will use a local variable to store the data that i will process
    local=[]
    # i will use a dictionary to store the statistics of the connections
    stats={}
    # i will use a variable to store my IP address so that i can know if the connection is incoming or outgoing
    myIp=get_if_addr(conf.iface)
    myMac=get_if_hwaddr(conf.iface)
    while True:
        if len(sharedData) > index:
            # in this if condition i check if there is new data in the list for me to use 

            #if there is i will take it and save it to variable local to my thread
            local=sharedData[index]
            # to save storage we could set the data in the list to None so that we know that this data was already processed
            #sharedData[index] = None

            # we increment the index so that we can check when new data is added to the list
            index += 1
        
        if local != []:
            # here i will process the data using the the local variable

            # i will check if the connection is incoming or outgoing
            
            if local['srcIp']!=myIp and local['dstIp']==myIp:
                # the connection is incoming
                # identify the connection by the source IP and port
                identifier=f"{local['srcIp']}:{local['srcPort']}/{local['dstIp']}:{local['dstPort']}"
                if identifier not in stats:
                    # if the connection is new i will add it to the dictionary
                    stats[identifier]={'Ack':local['ackNb'],
                                       'Seq':local['seqNb'],
                                       'flags':str(local['flags']),
                                       'srcMac':local['srcMac'],
                                       'time':int(local['time']),
                                       'srcPort':local['srcPort'],
                                       'srcIp':local['srcIp'],
                                       'dstPort':local['dstPort'],
                                       'dstIp':local['dstIp']
                                       }
                else:
                    newAck=local['ackNb']
                    newSeq=local['seqNb']
                    newFlags=str(local['flags'])
                    newSrcMac=local['srcMac']
                    newTime=local['time']
                    newMac=local['srcMac']


                    if newSrcMac!=stats[identifier]['srcMac']:
                        print("=============== Need to check ===============")

                    if 'R' in stats[identifier]['flags']:
                        # if the connection was reset previously, 
                        # check if someone is trying to open a new connection with syn flag
                        # of if someone is trying to continue the connection (which is when the attack happened)
                        if 'S' in newFlags:
                            stats[identifier]['flags']=newFlags
                            stats[identifier]['time']=newTime
                            stats[identifier]['srcMac']=newSrcMac
                            stats[identifier]['Ack']=newAck
                            stats[identifier]['Seq']=newSeq
                        else:
                            # if the connection was reset and someone is trying to continue it
                            # then an attack happened in the packet that sent the RST flag
                            print("=============== Attack detected ===============\nDetails of the connection that sent the RST flag:")
                            print(f"IP: {stats[identifier]['srcIp']}\nPort: {stats[identifier]['srcPort']}\nMAC: {stats[identifier]['srcMac']}\nTime: {stats[identifier]['time']}\nFlags: {stats[identifier]['flags']}\nAck: {stats[identifier]['Ack']}\nSeq: {stats[identifier]['Seq']}\nDst IP: {stats[identifier]['dstIp']}\nDst Port: {stats[identifier]['dstPort']}")
                            print("=============== =============== ===============\nDetails of the connection that tried to continue:")
                            print(f"IP: {local['srcIp']}\nPort: {local['srcPort']}\nMAC: {newMac}\nTime: {int(newTime)}\nFlags: {newFlags}\nAck: {newAck}\nSeq: {newSeq}\nDst IP: {local['dstIp']}\nDst Port: {local['dstPort']}")
                    else:
                        stats[identifier]['flags']=newFlags
                        stats[identifier]['time']=int(newTime)
                        stats[identifier]['srcMac']=newSrcMac
                        stats[identifier]['Ack']=newAck
                        stats[identifier]['Seq']=newSeq
            

            # after i'm done processing the data i will set the local variable to an empty list
            # so that i don't process the same data again
            local=[]
            # print(stats)



# this list will be used so the two threads can share data between them
# it is basically a queue shared between threads running concurrently
sharedData = []

# creating the threads
thread1 = threading.Thread(target=packetsniffer)
thread2 = threading.Thread(target=detectAttack, args=(sharedData,))

# starting the threads
thread1.start()
thread2.start()
