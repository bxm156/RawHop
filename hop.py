import socket
import struct
import time
import select
import math
import urllib
from xml.dom import minidom

ICMP_PROTO = socket.getprotobyname('icmp')
MAX_TTL = 255
LOW_TTL = 1 #127.0.0.1 returns 1
TIMEOUT_PER_PING = 3 #seconds
TARGET_PORT = 33534

########################
### Building Packets ###
########################

def build_ip_header(s,num,ttl,host):
    """
    Builds the IP Header for a given socket, ip number, ttl, and target host
    """
    source_ip, port = s.getsockname()

    ip_version = 4
    ip_internet_header_length = 5
    ip_tos = 0
    ip_total_length = 220
    ip_identification = num
    ip_fragment_offset = 0 
    ip_ttl = ttl
    ip_protocol = 17 # 17 = UDP
    ip_checksum = 0 # Depending on implementation, the kernel or the hardware will calculate this for us :)
    ip_source = socket.inet_aton(source_ip)
    ip_destination = socket.inet_aton(host)


    ip_ver_ihl = ( ip_version << 4) + ip_internet_header_length

    # The ! mark means network order
    # This code was written for an Intel Mac
    # Intel Macs are based on the Berkeley-derived kernels, which require a different byte order for
    # IP Headers.

    # On many Berkeley-derived kernels, all fields are in the 
    # network byte order except ip_len and ip_off, which are in host byte order
    
    ip_header = (struct.pack('!BB',ip_ver_ihl,ip_tos) + struct.pack('H',ip_total_length) + 
    struct.pack('!H',ip_identification) + struct.pack('H',ip_fragment_offset) + 
    struct.pack('!BB',ip_ttl,ip_protocol) + struct.pack('!H',ip_checksum) + 
    struct.pack('!4s4s',ip_source,ip_destination))

    return ip_header

def build_icmp(number):
    """
    Builds an ICMP Ping Request with a given id number
    """
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

def calc_icmp_checksum(data):
    """
    Calculates the ICMP checksum
    """
    s = 0
    for i in range(0, len(data), 2):
        w = (ord(data[i]) << 8) + ord(data[i+1])
        s = s + w
    s = (s  & 0xffff) + ( s >> 16)
    s = s + (s >> 16)
    return ~s & 0xffff

def build_udp(sport,dport,data):
    checksum = 0
    length = 8 + len(data)
    udp_header = struct.pack("!HHHH",sport,dport,length,checksum)
    udp_packet = udp_header + data
    #checksum = calc_udp_checksum(udp_packet)
    #udp_header = struct.pack("!HHHH",sport,dport,length,checksum)
    return udp_header + data

def calc_udp_checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        w = (ord(data[i]) << 8) + ord(data[i+1])
        s = s + w
    s = (s  & 0xffff) + ( s >> 16)
    s = s + (s >> 16)
    return ~s & 0xffff
###########################
### Response Validation ###
###########################

def receive_ping(my_socket, packet_id, icmp_id, time_sent, timeout):
    """
    Listens on my_socket for a packet_id and icmp_id. It uses the time_sent to 
    determine the RTT. We wait no longer than timeout.

    Returns a tuple (Bool,Bool or RTT).
        The first boolean is if we recieved a reply.
        If we did recieve a reply, the second value is the RTT otherwise False
        
    """
    # Receive the ping from the socket.
    time_left = timeout
    while True:
        started_select = time.time()
        ready = select.select([my_socket], [], [], time_left)
        how_long_in_select = time.time() - started_select
        if ready[0] == []: # Timeout
            return (False, False)
        time_received = time.time()
        rec_packet, addr = my_socket.recvfrom(1024)
        correct_packet, reply = validate_icmp_response(rec_packet,packet_id,icmp_id)
        if correct_packet == True:
            return (reply, time_received - time_sent)
        time_left -= time_received - time_sent
        if time_left <= 0:
            return (False, False)

def validate_icmp_response(response,sent_ip_id,sent_icmp_id):
    """
    Validates a possible reply to our ping request

    Returns a tuple (Bool,Bool).
        The first boolean is if recieved a response for our pocket (False if packet is not related). 
        If we did recieve a response to our ping, return True if it was successfull,
            False if the TTL expired during transit.
    """
    icmp_header = response[20:28] #Extract the ICMP Response
    icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_sequence = struct.unpack('!bbHHh', icmp_header)
    if icmp_type == 3 and icmp_code == 3:
        #We have recieved a valid ICMP response!
        return (True,True)

    #We may have an expired TTL...
    original_ip_header =  response[28:48]
    (ip_ver_hl, ip_tos, ip_len, ip_ident, ip_offset, ip_ttl, ip_proto, ip_checksum, 
        ip_src, ip_dest) = struct.unpack('!BBHHHBBH4s4s', original_ip_header)

    original_icmp_header = response[48:56]
    (original_icmp_type, original_icmp_code, original_icmp_checksum, original_icmp_id,
        original_icmp_seq) = struct.unpack('!bbHHh',original_icmp_header)
    if icmp_type == 11 and icmp_code == 0 and ip_ident == sent_ip_id:
        #The TTL Expired!
        return (True,False)
    print icmp_type, icmp_code
    #Throw away
    return (False, False)

###################################
### Geographical Distance - 425 ###
###################################

def distance(lat1,long1,lat2,long2):
    """ 
    Using the Haversine forumula
    """
    r = 6378.1 #radius of Earth in km
    dLat = math.radians(lat2-lat1)
    dLong = math.radians(long2-long1)
    a = math.sin(dLat/2) * math.sin(dLat/2) + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * \
        math.sin(dLong/2) * math.sin(dLong/2)
    c = 2 * math.atan2(math.sqrt(a),math.sqrt(1-a))
    d = r * c
    return d # distance in km

def get_coordinates(ip):
    """
    Returns the latitude and longitude for a IP address
    """
    url = "http://freegeoip.net/xml/{}".format(ip)
    dom = minidom.parse(urllib.urlopen(url))
    lat = dom.getElementsByTagName('Latitude')[0].childNodes[0].nodeValue
    long = dom.getElementsByTagName('Longitude')[0].childNodes[0].nodeValue
    return (float(lat),float(long))

########################
### Program Exection ###
########################

def run_search(s,host):
    """
    Runs a 'binary' search to find the minimum TTL value, and its RTT
    """
    starting_ttl = 16 #defined in homework assignment
    starting_packet_id = 500
    starting_icmp_id = 100

    low = 0
    high = MAX_TTL
    ttl = starting_ttl
    last_rtt = None

    while True:
        # Build Packet
        packet = build_ip_header(s,starting_packet_id,ttl,host) + build_udp(5337,TARGET_PORT,192*"Q")
        s.sendto(packet,("1.3.3.7",0)) #destination host doesn't matter, we make our own ip header
        (success,rtt) = receive_ping(s,starting_packet_id,starting_icmp_id, time.time(), TIMEOUT_PER_PING)
        if rtt is not False:
            last_rtt = rtt
        print "{} - {} {}".format(ttl,success,rtt)
        if success:
            high = ttl
            new_ttl = max((high+low)/2,LOW_TTL)
            if ttl == new_ttl:
                return (False,False)
            ttl = new_ttl
        else:
            low = ttl
            new_ttl = min(ttl*2,MAX_TTL)
            if ttl == new_ttl:
                return (False, False)
            ttl = new_ttl
        if high == (low + 1):
            return (high,last_rtt)

##################
### Main Entry ###
##################

def run(host):
    local_ip = socket.gethostbyname(socket.gethostname())
    
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    print run_search(s,host)
    lat1,long1 = get_coordinates(local_ip)
    lat2,long2 = get_coordinates(host)
    print distance(lat1,long1,lat2,long2)
    s.close()

if __name__ == "__main__":
    run("74.125.134.101")

