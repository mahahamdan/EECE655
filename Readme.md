## TCP Reset Attack :

### Group 2:

- Maha Hamdan
- Mounir Khalil
- Bechara Rizk
- Batoul Fakha

### Conduct an attack:

We launched two virtual machines X and Y using Oracle virtual Box with the bellow settings 

<br>

![Diagram](./Screenshots/MachineX%20Settings.png)
![Diagram](./Screenshots/MachineY%20Settings.png)
 
<br>
Using ifconfig command we detected the ip of each machine 
<br>

##### IP for Machine X is 192.168.0.103
![Diagram](./Screenshots/mx%20ifconfig.png)

##### IP for Machine Y is 192.168.0.104
![Diagram](./Screenshots/MY%20ifconfig.png)

<br>
Then we connected between them using Telnet (an application layer protocol that operates over TCP)

![Diagram](./Screenshots/telnetcxn.png)
![Diagram](./Screenshots/telnet%20cxn%202.png)

##### Attack Succeeded !!
After running the code of conductAttack the connection disabled and reset attack succeeded !

![Diagram](./Screenshots/Attacksucceed.png)

We can view the reset packet sent using wireshark 
![Diagram](./Screenshots/Wireshark.png)



