import socket
import struct
import time
import select

ICMP_PROTO = socket.getprotobyname('icmp')

def build_ip_header(s,num,ttl,host):
    source_ip, port = s.getsockname()

    ip_version = 4
    ip_internet_header_length = 0
    ip_tos = 0
    ip_total_length = 0
    ip_identification = num
    ip_fragment_offset = 0 
    ip_ttl = ttl
    ip_protocol = 1 # 1 = ICMP
    ip_checksum = 0
    ip_source = socket.inet_aton(source_ip)
    ip_destination = host


    ip_ver_ihl = ( ip_version << 4) + ip_internet_header_length

    # The ! mark means network order
    ip_header = struct.pack('!BBHHHBBH4s4s',ip_ver_ihl,ip_tos,ip_total_length,
        ip_identification, ip_fragment_offset, ip_ttl, ip_protocol,
        ip_checksum, ip_source, ip_destination)
    return ip_header

def calc_icmp_checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        w = (ord(data[i]) << 8) + ord(data[i+1])
        s = s + w
    s = (s  & 0xffff) + ( s >> 16)
    s = s + (s >> 16)
    return ~s & 0xffff

def build_icmp(number):
    icmp_type = 8
    icmp_code = 0
    icmp_checksum = 0
    icmp_id = number
    icmp_seq = 1
    icmp_data = 192*'Q'
    icmp_header = struct.pack('bbHHh',icmp_type,icmp_code,icmp_checksum,icmp_id,icmp_seq)
    icmp_checksum = socket.htons(calc_icmp_checksum(icmp_header + icmp_data))
    icmp_header = struct.pack('bbHHh',icmp_type,icmp_code,icmp_checksum,icmp_id,icmp_seq)
    return icmp_header + icmp_data

def receive_ping(my_socket, packet_id, time_sent, timeout):
        # Receive the ping from the socket.
        time_left = timeout
        while True:
            started_select = time.time()
            ready = select.select([my_socket], [], [], time_left)
            how_long_in_select = time.time() - started_select
            if ready[0] == []: # Timeout
                return
            time_received = time.time()
            rec_packet, addr = my_socket.recvfrom(1024)
            icmp_header = rec_packet[20:28]
            type, code, checksum, p_id, sequence = struct.unpack(
                'bbHHh', icmp_header)
            if p_id == packet_id:
                return time_received - time_sent
            time_left -= time_received - time_sent
            if time_left <= 0:
                return

def run(host):
    HOST = socket.gethostbyname(socket.gethostname())
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW, ICMP_PROTO)

    #Since we are using socket.IPPROTO_RAW, we do not need the following line.
    #s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 0)
    packet = build_icmp(1989)
    s.sendto(packet,(host,1))
    
    delay = receive_ping(s, 1989, time.time(), 3)
    print delay
    #s.bind((HOST,0))
    #build_ip_header(s,1,16,host)
    s.close()

if __name__ == "__main__":
    run("8.8.8.8")

