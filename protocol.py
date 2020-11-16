import struct
import os
import socket


def init_socket(nic):
    ETH_P_ALL = 0x0003

    # 开启混杂模式
    os.system('ip link set ens33 promisc on')
    # 关闭网卡特性
    os.system('ethtool -K ens33 gro off')

    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((nic, 0))

    return s


def parse_eth(data):
    # eth
    packet = {}

    data_len = len(data) - 14
    eth_fmt = '!6s6s2s%ds' % data_len
    eth_tuple = struct.unpack(eth_fmt, data)

    packet['smac'] = eth_tuple[1]
    packet['dmac'] = eth_tuple[0]
    packet['type'] = eth_tuple[2]
    packet['eth_data'] = eth_tuple[3]

    return packet


def parse_ip(data):
    # ip
    packet = {}

    data_len = len(data) - 20
    ip_fmt = '!1s1s2s2s2s1s1s2s4s4s%ds' % data_len
    ip_tuple = struct.unpack(ip_fmt, data)

    packet['version_header_length'] = ip_tuple[0]
    packet['services_field'] = ip_tuple[1]
    packet['total_length'] = ip_tuple[2]
    packet['identification'] = ip_tuple[3]
    packet['ip_flags'] = ip_tuple[4]
    packet['time_to_live'] = ip_tuple[5]
    packet['protocol'] = ip_tuple[6]
    packet['ip_checksum'] = ip_tuple[7]
    packet['src'] = ip_tuple[8]
    packet['dst'] = ip_tuple[9]
    packet['ip_data'] = ip_tuple[10]

    return packet


def parse_tcp(data):
    # tcp
    packet = {}

    data_len = len(data) - 20
    tcp_fmt = '!2s2s4s4s1s1s2s2s2s%ds' % data_len
    tcp_tuple = struct.unpack(tcp_fmt, data)

    packet['sport'] = tcp_tuple[0]
    packet['dport'] = tcp_tuple[1]
    packet['seq_num'] = tcp_tuple[2]
    packet['ack_num'] = tcp_tuple[3]
    packet['header_length'] = tcp_tuple[4]
    packet['tcp_flags'] = tcp_tuple[5]
    packet['window_size_value'] = tcp_tuple[6]
    packet['tcp_checksum'] = tcp_tuple[7]
    packet['urgent_pointer'] = tcp_tuple[8]
    packet['tcp_data'] = tcp_tuple[9]

    return packet


def parse_packet(data):
    packet = {}

    eth_packet = parse_eth(data)
    packet.update(eth_packet)
    if eth_packet['type'] != b'\x08\x00':
        return packet

    ip_packet = parse_ip(packet['eth_data'])
    packet.update(ip_packet)
    if ip_packet['protocol'] != b'\x06':
        return packet

    tcp_packet = parse_tcp(packet['ip_data'])
    packet.update(tcp_packet)

    return packet


def compute_checksum(data):
    # padding
    if len(data) % 2 == 1:
        data += b'\x00'

    # add
    checksum = 0
    for i in range(int(len(data) / 2)):
        checksum += data[i * 2] * 0x100 + data[i * 2 + 1]

    # 32 -> 16
    while checksum > 0x10000:
        checksum = int(checksum / 0x10000) + (checksum % 0x10000)

    # 0xffff diff
    checksum = 0xffff - checksum

    bytes_checksum = struct.pack('!H', checksum)

    return bytes_checksum