import socket
import struct
import time
import select

ICMP_PROTO = socket.getprotobyname('icmp')

def build_ip_header(s,num,ttl,host):
    source_ip, port = s.getsockname()

    ip_version = 4
    ip_internet_header_length = 5
    ip_tos = 0
    ip_total_length = 220
    ip_identification = num
    ip_fragment_offset = 0 
    ip_ttl = ttl
    ip_protocol = 1 # 1 = ICMP
    ip_checksum = 0
    ip_source = socket.inet_aton(source_ip)
    ip_destination = socket.inet_aton(host)


    ip_ver_ihl = ( ip_version << 4) + ip_internet_header_length

    # The ! mark means network order
    # This code was written for an Intel Mac
    # Intel Macs are based on the Berkeley-derived kernels, which require a different byte order for
    # IP Headers.

    # On many Berkeley-derived kernels, all fields are in the 
    # network byte order except ip_len and ip_off, which are in host byte order
    
    ip_header = struct.pack('!BB',ip_ver_ihl,ip_tos) + struct.pack('H',ip_total_length) + struct.pack('!H',ip_identification) + struct.pack('H',ip_fragment_offset) + struct.pack('!BB',ip_ttl,ip_protocol) + struct.pack('!H',ip_checksum) + struct.pack('!4s4s',ip_source,ip_destination)

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
    icmp_header = struct.pack('!bbHHh',icmp_type,icmp_code,icmp_checksum,icmp_id,icmp_seq)
    icmp_checksum = calc_icmp_checksum(icmp_header + icmp_data)
    icmp_header = struct.pack('!bbHHh',icmp_type,icmp_code,icmp_checksum,icmp_id,icmp_seq)
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
                '!bbHHh', icmp_header)
            if p_id == packet_id:
                return time_received - time_sent
            time_left -= time_received - time_sent
            if time_left <= 0:
                return

def run(host):
    HOST = socket.gethostbyname(socket.gethostname())
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW, ICMP_PROTO)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    packet = build_ip_header(s,150,255,host) + build_icmp(1989)

    s.sendto(packet,("4.4.4.4",0))
    
    delay = receive_ping(s, 1989, time.time(), 3)
    print delay
    #s.bind((HOST,0))
    #build_ip_header(s,1,16,host)
    s.close()

if __name__ == "__main__":
    run("8.8.8.8")

