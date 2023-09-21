import socket
from random import randint
from subprocess import call, PIPE

timeout = 10
http_version = 'HTTP/1.1'

# reserved local administrative scope multicast address
broadcast = '239.255.255.250:1900'

# discovery request message

'''
Discovery occurs when a SSDP client multicasts a HTTP UDP discovery
request to the SSDP multicast channel/Port

M-SEARCH = method
ST = Search Target
MX = Maximum Wait
MAN = Mandatory Extension
'''
msg = \
    f'M-SEARCH * {http_version}\r\n' \
    f'HOST:{broadcast}\r\n' \
    'ST:upnp:rootdevice\r\n' \
    f'MX:{timeout}\r\n' \
    'MAN:"ssdp:discover"\r\n' \
    '\r\n'

call("clear", shell=True, stdout=PIPE)

# setup UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

sock.settimeout(timeout)
sock.sendto(bytes(msg, encoding='utf-8'), (
            broadcast.split(':')[0],
            int(broadcast.split(':')[1])
))

try:
    while True:
        data, addr = sock.recvfrom(randint(1024, 65535))
        print(f'{addr[0]}:{addr[1]} =>', data.decode('utf-8'))

except socket.timeout:
    print('Reached max wait delay upon network discovery..\n')
