"""
  The real stuff. 
"""

import socket,sys,struct

import os

#-----------------------------------------------------------------------------


#-----------------------------------------------------------------------------
def get_mac_address(bytesString):
  bytesString = map('{:02x}'.format, bytesString)
  destination_mac = ':'.join(bytesString).upper()
  return destination_mac

#-----------------------------------------------------------------------------
'''
def print_summary(pkt):
    if IP in pkt:
        ip_src=pkt[IP].src
        ip_dst=pkt[IP].dst
    if TCP in pkt:
        tcp_sport=pkt[TCP].sport
        tcp_dport=pkt[TCP].dport

        print (" IP src " + str(ip_src) + " TCP sport " + str(tcp_sport))
        print (" IP dst " + str(ip_dst) + " TCP dport " + str(tcp_dport))
        print ("")

    if ((pkt[IP].src == "192.168.0.1") or (pkt[IP].dst == "192.168.0.1")):
	    print ("[!]")
'''

#-----------------------------------------------------------------------------
def main():

  if len(sys.argv) == 2:
    filtro = sys.argv[1]
  else: 
    print(sys.argv[0] + " <Filtro>")

  # create a network socket using the default constructor
  try:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
  except socket.error:
    print('Socket não pode ser criado.')
    sys.exit(1)


  # while loop runs infinitely to capture any incoming packets
  while True:
      # listen on port 65565
      raw_data, address = sock.recvfrom(65565)
      destination_mac, src_mac, ethernet_proto = struct.unpack('! 6s 6s H', raw_data[:14])
      src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = struct.unpack(
            '! H H L L H H H H H H', raw_data[:24])

      version_header_len = raw_data[0]
      version = version_header_len >> 4
      header_len = (version_header_len & 15) * 4
      ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])


      # packet parameters
      destination_mac = get_mac_address(destination_mac)
      src_mac = get_mac_address(src_mac)
      ethernet_proto = socket.htons(ethernet_proto)
      data = raw_data[14:]
    
      #print('\nPacote:')
      #print('\tDestino: {}, Origem: {}, Protocolo: {}'.format(destination_mac, src_mac, ethernet_proto))

      if filtro == 'IPV6':
        print('IPV6')
      elif filtro == 'IPV4':
        # analyse only IPv4 packets (I know IPv6 is the real deal but this should work for now)
        if (ethernet_proto == 8):
            version_header_len = data[0]
            version = version_header_len >> 4
            header_len = (version_header_len & 15) * 4
            ttl,proto,src,target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
           
            src = '.'.join(map(str,src)) 
            target = '.'.join(map(str,target)) 
            
            print('IPv4 packet:')
            print('\tVersion: {}, Header length: {}, TTL: {}'.format(version,header_len,ttl))
            print('\tProtocol: {}, Source: {}, Target: {}'.format(proto,src,target))
            print('***************************************************************')
            print('\ACK: {}, flag ACK: {}'.format(acknowledgment,flag_ack))
      
      elif filtro == 'ICMP':
        icmp_type, code, checksum = struct.unpack('! B B H',  raw_data[:4])
        print ("*******************ICMP***********************")
        print ("\tICMP type: %s" % (icmp_type))
        print ("\tICMP code: %s" % (code))
        print ("\tICMP checksum: %s" % (checksum))  
      
      elif filtro == 'UDP':          
        print('UDP')
        print (" ")
        (src_port, dest_port, sequence, acknowledgement, offset_reserved_flag) = struct.unpack('! H H L L H', data[:14])
        print("*******************UDPv4***********************")
        print('Version: {}\nHeader Length: {}\nTTL: {}'.format(version, version_header_len, ttl))
        print('protocol: {}\nSource: {}\nTarget: {}'.format(proto, src, target))
        print('*****UDP Segment*****')
        print('Source Port: {}\nDestination Port: {}\nLength: {}'.format(src_port, dest_port, header_len))

        offset = (offset_reserved_flag >> 12) * 4
        flag_urg = (offset_reserved_flag & 32) >> 5
        flag_ack = (offset_reserved_flag & 32) >> 4
        flag_psh = (offset_reserved_flag & 32) >> 3
        flag_rst = (offset_reserved_flag & 32) >> 2
        flag_syn = (offset_reserved_flag & 32) >> 1
        flag_fin = (offset_reserved_flag & 32) >> 1
        print('flag_urg {}, flag_ack {}, flag_psh {}, flag_rst {}, flag_syn {}, flag_fin {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
        
      



#-----------------------------------------------------------------------------
if __name__ == "__main__":
    main()
#-----------------------------------------------------------------------------
