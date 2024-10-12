import socket
from struct import pack, unpack
import sys



def packet_sniff():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    while True:
        raw_packet = s.recv(65565)

        # first byte
        first_byte = raw_packet[0]

        # version
        version = (first_byte >> 4) & 0x0F
        print(version)

        # IHL
        ihl = first_byte & 0x0F
        print(ihl)

        # TOS 
        tos = raw_packet[1:2]
        tos_value = unpack('B', tos)[0]
        print(tos_value)

        # identification
        identification = raw_packet[4:6]
        print('ID: ', unpack('H', identification))

        #protocol
        protocol_value = raw_packet[9]
        if protocol_value==6:
            print('Protocol: TCP')
        if protocol_value==17:
            print('Protocol: UDP')

        # IP flags
        ip_flags_byte = raw_packet[6]
        ip_flags = (ip_flags_byte >> 5) & 0x07
        print(ip_flags)

        # source ip
        source_ip = raw_packet[12:16]
        print(unpack('BBBB', source_ip))

        # dest ip
        dest_ip = raw_packet[16:20]
        print(unpack('BBBB', dest_ip))


packet_sniff()
