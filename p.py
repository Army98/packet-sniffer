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
        # shift right 4 because the bit value would be too high
        version = (first_byte >> 4) & 0x0F
        print(version)

        # IHL
        ihl = first_byte & 0x0F
        print('Header Length: ', ihl)

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

        ip_header_length = ihl * 4  
        
        transport_layer_start = ip_header_length

        if protocol_value in (6, 17):  
            source_port, destination_port = unpack('!HH', raw_packet[transport_layer_start:transport_layer_start + 4])

            print(f"Source Port: {source_port}")
            print(f"Destination Port: {destination_port}")

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
