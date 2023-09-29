import threading
from scapy.all import *

# we will use threading to run multiple functions at the same time 
# and thus not lose any packet while processing the data
# we will use Scapy python library for network analysis (capture and analyze
# TCP packets in real-time)

# Batoul's part
# function to sniff and format data
def packetsniffer():
    while True:
        #capture TCP packets indefinitely and without storing internally
        packet = sniff(filter="tcp", prn=packet_sniffer, store=False) 
       
        #extract information from the packet 

    
        #create dictionnary to store packet information 
        packet_info = {
        
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
