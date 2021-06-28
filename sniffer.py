import socket
import struct
import binascii
import struct
import sys

def main():
    if len(sys.argv) == 2:
        filtro = sys.argv[1]
    else: 
        print(sys.argv[0] + " <Filter>")
        sys.exit(1)
    
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except socket.error:
        print('Socket could not be created.')
        sys.exit(1)
    
    while True:
        raw_data, addr = conn.recvfrom(65536)
        ethernet_protocol = ""
        IpHeader = struct.unpack("!6s6sH",raw_data[0:14])
        destination_mac = binascii.hexlify(IpHeader[0]) 
        source_mac = binascii.hexlify(IpHeader[1]) 
        protoType = IpHeader[2] 
        next_protocol = hex(protoType) 

        if (next_protocol == '0x800'): 
            ethernet_protocol = 'IPV4'
        elif (next_protocol == '0x86dd'): 
            ethernet_protocol = 'IPV6'

        data = raw_data[14:]
        
        if (ethernet_protocol == 'IPV6'):
            ipv6_first_word, ipv6_payload_legth, next_protocol, ipv6_hoplimit = struct.unpack(">IHBB", data[0:8])
            ipv6_src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
            ipv6_dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])

            bin(ipv6_first_word)
            "{0:b}".format(ipv6_first_word)
            version = ipv6_first_word >> 28
            traffic_class = ipv6_first_word >> 16
            traffic_class = int(traffic_class) & 4095
            flow_label = int(ipv6_first_word) & 65535

            if (next_protocol == 6):
                next_protocol = 'TCP'
            elif (next_protocol == 17):
                next_protocol = 'UDP'
            elif (next_protocol == 58):
                next_protocol = 'ICMPv6'

            new_packet = data[40:]

            if ((next_protocol == 'ICMPv6') and (filtro == 'ICMP')):
                type, code, chekcsum = struct.unpack(">BBH", new_packet[:4])

                print('  --  ICMP v6  --  ')
                print('Type: %s' % type)
                print('Code: %s' % code)
                print('Checksum: %s' % chekcsum)
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
                print('Source Port: %s' % srcPort)
                print('Destination Port: %s' % dstPort)
                print('Sequence Number: %s' % sqncNum)
                print('Ack. Number: %s' % acknNum)
                print('Data Offset: %s' % dataOffset)
                print('Reserved: %s' % reserved)
                print('TCP Flags: %s' % tcpFlags) 
                print('Window: %s' % window)
                print('Checksum: %s' % checkSum)
                print('Urgent Pointer: %s' % urgPntr)
                print(' ')
                
            elif ((next_protocol == 'UDP') and (filtro == 'UDP')):
                packet = struct.unpack("!4H", new_packet[0:8])
                srcPort = packet[0]
                dstPort = packet[1]
                lenght = packet[2]
                checkSum = packet[3]

                print('  --  UDP v6 --  ')
                print('Source Port: %s' % srcPort)
                print('Destination Port: %s' % dstPort)
                print('Lenght: %s' % lenght)
                print('Checksum: %s' % checkSum)
                print(' ')

        elif (ethernet_protocol == 'IPV4'):    
            version_header_len = data[0]
            version = version_header_len >> 4
            header_length = (version_header_len & 15) * 4
            ttl, protocol, source , target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
            source = '.'.join(map(str, source))
            target = '.'.join(map(str, target))            
            data = data[header_length:]

            if ((protocol == 1) and (filtro == 'ICMP')):
                icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
                data = data[4:]
 
                print("  --  ICMP v4 --  ")
                print("ICMP type: %s" % icmp_type)
                print("ICMP code: %s" % code)
                print("ICMP checksum: %s" % checksum)
                print(' ')

            elif ((protocol == 6) and (filtro == 'TCP')):
                print("  --  TCP v4  --  ")
                print('Version: %s' % version)
                print('Header Length: %s' % header_length)
                print('TTL: %s' % ttl)
                print('Protocol: %s' % protocol)
                print('Source: %s' % source)
                print('Target: %s' % target)
                print('')

                source_port, destination_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = struct.unpack(
                    '! H H L L H H H H H H', raw_data[:24])
                
                print('\t  ---  TCP Segment  ---  ')
                print('\tSource Port: %s' % source_port)
                print('\tDestination Port: %s' % destination_port)
                print('\tSequence: %s' % sequence)
                print('\tAcknowledgment: %s' % acknowledgment)
                print('')

                print('\t  ---  Flags  ---  ')
                print('\tURG: %s' % flag_urg)
                print('\tACK: %s' % flag_ack)
                print('\tPSH: %s' % flag_psh)
                print('\tRST: %s' % flag_rst)
                print('\tSYN: %s' % flag_syn)
                print('\tFIN: %s' % flag_fin)
                print('')

            elif ((protocol == 17) and (filtro == 'UDP')):
                print("  --  UDP v4  --  ")
                print('Version: %s' % version)
                print('Header Length: %s' % header_length)
                print('TTL: %s' % ttl)
                print('Protocol: %s' % protocol)
                print('Source: %s' % source)
                print('Target: %s' % target)
                print('')

                source_port, destination_port, length = struct.unpack('! H H 2x H', data[:8])
                data = data[8:]
                print('\t  ---  UDP Segment  ---  ')
                print('\tSource Port: %s' % source_port)
                print('\tDestination Port: %s' % destination_port)
                print('\tLength: %s' % length)
                print('')

main()
