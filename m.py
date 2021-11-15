import sys
import socket
from datetime import datetime
#Libraries imported

target='127.0.0.1'
print("-" * 50)
print("Scanning Target: " + target)
print("Scanning started at:" + str(datetime.now()))
print("-" * 50)

try:
    port=23
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    result = s.connect_ex((target, port))
    s.close()


    porti=2323
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    resulti = s.connect_ex((target, porti))
    s.close()

    if result!=0 and resulti!=0:
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

