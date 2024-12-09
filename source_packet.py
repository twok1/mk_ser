import socket
from scapy.all import *
from scapy.all import Ether, LLC

MY_ADDRESS = 177


class SourcePacket:
    def __init__(self, ssap=MY_ADDRESS):
        self.dsap = 0
        self.ssap = ssap

    def address_list(self, address):
        address_list = [address // 100] + [address % 100]
        while len(address_list) < 5:
            address_list = [0] + address_list
        return bytes_encode([2] + address_list)

    @property
    def ssap(self):
        return self._ssap
    
    @ssap.setter
    def ssap(self, value: int):
        self._ssap = self.address_list(value)

    @property
    def dsap(self):
        return self._dsap
    
    @dsap.setter
    def dsap(self, value: int):
        self._dsap = self.address_list(value)

    
    def collect_eth_title(self):
        self._eth_title = Ether(dst=self.dsap, src=self.ssap)

    def collect_llc_title(self):
        self._llc = LLC(dsap=80, ssap=80, ctrl=103)

    def write_packet_from_data(self, data: bytes):
        pass


def adr_from_list(list):
    return sum([100 ** (4 - num) * i for num, i in enumerate(list)])

def get_addresses(data):
    dst = adr_from_list(data[1:6])
    src = adr_from_list(data[7:12])
    data_raw = data[17:]
    return dst, src, data_raw

def mks_telegram(data):
    print(data)
    time_a, time_b = data[7:9], data[9:11]
    print(bytes_bin(time_a), bytes_bin(time_b))

def bytes_bin(data):
    return ''.join(map(lambda x: bin(x).lstrip('0b'), data))


packet_list = [2, 0, 0, 0, 7, 99, 2, 0, 0, 0, 1, 19, 0, 30, 80, 80, 231, 239, 25, 210, 0, 17, 0, 101, 51, 122, 160, 111, 15, 254, 0, 0, 0, 0, 0, 0, 192, 6, 192, 0, 192, 6, 17, 4, 136, 136, 136, 136, 136, 136, 136, 136, 136, 136, 136, 136, 136, 136, 136, 136]
dst, src, data_raw = get_addresses(packet_list)
opc = data_raw[2]
if opc == 210:
    mks_telegram(data_raw)