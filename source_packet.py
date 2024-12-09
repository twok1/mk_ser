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


s = SourcePacket()
s.dsap = 119
s.collect_eth_title()

packet = Ether(s._eth_title)
packet.show()
print(hexdump(packet))