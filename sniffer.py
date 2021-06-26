import socket
import struct
import textwrap
import binascii
import struct
import sys

def main():
    if len(sys.argv) == 2:
        filtro = sys.argv[1]
    else: 
        print(sys.argv[0] + " <Filtro>")
        sys.exit(1)
    
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except socket.error:
        print('Socket could not be created.')
        sys.exit(1)

    while True:
        raw_data, addr = conn.recvfrom(65536)
        destination_mac, source_mac, ethernet_protocol, data = unpackEthernetFrame(raw_data)

        if (ethernet_protocol == 'IPV6'):
            new_packet, next_protocol = ipv6Header(data)

            if ((next_protocol == 'ICMPv6') and (filtro == 'ICMP')):
                type, code, chekcsum = struct.unpack(">BBH", new_packet[:4])

                print('  --  ICMP v6  --  ')
                print('\tType: %s' % type)
                print('\tCode: %s' % code)
                print('\tChecksum: %s' % chekcsum)
                print(' ')

            elif ((next_protocol == 'TCP') and (filtro == 'TCP')):
                packet = struct.unpack("!2H2I4H", new_packet[0:20])
                srcPort = packet[0]
                dstPort = packet[1]
                sqncNum = packet[2]
                acknNum = packet[3]
                dataOffset = packet[4] >> 12
                reserved = (packet[4] >> 6) & 0x003F
                tcpFlags = packet[4] & 0x003F 
                window = packet[5]
                checkSum = packet[6]
                urgPntr = packet[7]

                print('  --  TCP v6 --  ')
                print('\tSource Port: %s' % srcPort)
                print('\tDestination Port: %s' % dstPort)
                print('\tSequence Number: %s' % sqncNum)
                print('\tAck. Number: %s' % acknNum)
                print('\tData Offset: %s' % dataOffset)
                print('\tReserved: %s' % reserved)
                print('\tTCP Flags: %s' % tcpFlags) 
                print('\tWindow: %s' % window)
                print('\tChecksum: %s' % checkSum)
                print('\tUrgent Pointer: %s' % urgPntr)
                print(' ')
                
            elif ((next_protocol == 'UDP') and (filtro == 'UDP')):
                packet = struct.unpack("!4H", new_packet[0:8])
                srcPort = packet[0]
                dstPort = packet[1]
                lenght = packet[2]
                checkSum = packet[3]

                print('  --  UDP v6 --  ')
                print('\tSource Port: %s' % srcPort)
                print('\tDestination Port: %s' % dstPort)
                print('\tLenght: %s' % lenght)
                print('\tChecksum: %s' % checkSum)
                print(' ')

        elif (ethernet_protocol == 'IPV4'):
            (version, header_length, ttl, protocol, source, target, data) = unpackIPv4Packet(data)

            if ((protocol == 1) and (filtro == 'ICMP')):
                icmp_type, code, checksum, data = unpackIcmpPacket(data)

                print("  --  ICMP v4 --  ")
                print("\tICMP type: %s" % icmp_type)
                print("\tICMP code: %s" % code)
                print("\tICMP checksum: %s" % checksum)
                print(' ')

            elif ((protocol == 6) and (filtro == 'TCP')):
                print("  --  TCP v4  --  ")
                print('\tVersion: %s' % version)
                print('\tHeader Length: %s' % header_length)
                print('\tTTL: %s' % ttl)
                print('\tProtocol: %s' % protocol)
                print('\tSource: %s' % source)
                print('\tTarget: %s' % target)
                print('')

                source_port, destination_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = struct.unpack(
                    '! H H L L H H H H H H', raw_data[:24])
                
                print('\t  ---  TCP Segment  ---  ')
                print('\t\tSource Port: %s' % source_port)
                print('\t\tDestination Port: %s' % destination_port)
                print('\t\tSequence: %s' % sequence)
                print('\t\tAcknowledgment: %s' % acknowledgment)
                print('')

                print('\t  ---  Flags  ---  ')
                print('\t\tURG: %s' % flag_urg)
                print('\t\tACK: %s' % flag_ack)
                print('\t\tPSH: %s' % flag_psh)
                print('\t\tRST: %s' % flag_rst)
                print('\t\tSYN: %s' % flag_syn)
                print('\t\tFIN: %s' % flag_fin)
                print('')

            elif ((protocol == 17) and (filtro == 'UDP')):
                print("  --  UDP v4  --  ")
                print('\tVersion: %s' % version)
                print('\tHeader Length: %s' % header_length)
                print('\tTTL: %s' % ttl)
                print('\tProtocol: %s' % protocol)
                print('\tSource: %s' % source)
                print('\tTarget: %s' % target)
                print('')

                source_port, destination_port, length, data = unpackUdpSegment(data)

                print('\t  ---  UDP Segment  ---  ')
                print('\t\tSource Port: %s' % source_port)
                print('\t\tDestination Port: %s' % destination_port)
                print('\t\tLength: %s' % length)
                print('')

def unpackIPv4Packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, protocol, source, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])

    return version, header_len, ttl, protocol, formatIPv4(source), formatIPv4(target), data[header_len:]

def nextHeader(ipv6_next_header):
    if (ipv6_next_header == 6):
        ipv6_next_header = 'TCP'
    elif (ipv6_next_header == 17):
        ipv6_next_header = 'UDP'
    elif (ipv6_next_header == 43):
        ipv6_next_header = 'Routing'
    elif (ipv6_next_header == 1):
        ipv6_next_header = 'ICMP'
    elif (ipv6_next_header == 58):
        ipv6_next_header = 'ICMPv6'
    elif (ipv6_next_header == 44):
        ipv6_next_header = 'Fragment'
    elif (ipv6_next_header == 0):
        ipv6_next_header = 'HOPOPT'
    elif (ipv6_next_header == 60):
        ipv6_next_header = 'Destination'
    elif (ipv6_next_header == 51):
        ipv6_next_header = 'Authentication'
    elif (ipv6_next_header == 50):
        ipv6_next_header = 'Encapsuling'

    return ipv6_next_header

def ipv6Header(data):
    ipv6_first_word, ipv6_payload_legth, ipv6_next_header, ipv6_hoplimit = struct.unpack(">IHBB", data[0:8])
    ipv6_src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
    ipv6_dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])

    bin(ipv6_first_word)
    "{0:b}".format(ipv6_first_word)
    version = ipv6_first_word >> 28
    traffic_class = ipv6_first_word >> 16
    traffic_class = int(traffic_class) & 4095
    flow_label = int(ipv6_first_word) & 65535

    ipv6_next_header = nextHeader(ipv6_next_header)
    data = data[40:]

    return data, ipv6_next_header

def unpackEthernetFrame(data):
    protocol = ""
    IpHeader = struct.unpack("!6s6sH",data[0:14])
    dstMac = binascii.hexlify(IpHeader[0]) 
    srcMac = binascii.hexlify(IpHeader[1]) 
    protoType = IpHeader[2] 
    next_protocol = hex(protoType) 

    if (next_protocol == '0x800'): 
        protocol = 'IPV4'
    elif (next_protocol == '0x86dd'): 
        protocol = 'IPV6'

    data = data[14:]

    return dstMac, srcMac, protocol, data

def unpackIcmpPacket(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])

    return icmp_type, code, checksum, data[4:]

def unpackUdpSegment(data):
    source_port, destination_port, size = struct.unpack('! H H 2x H', data[:8])

    return source_port, destination_port, size, data[8:]

def formatIPv4(addr):
    return '.'.join(map(str, addr))

main()