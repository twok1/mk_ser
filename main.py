import socket
from scapy.all import *
from scapy.all import Ether, LLC

MY_ADDRESS = 763
BD = b'\xef' 


def stb(string: str) -> bytes:
    """кодируем строку в байты (для меньше букв)"""
    return str.encode(string)

class MkeTelegram:
    def __init__(self, src=0, dst=0) -> None:
        self._src = src
        self._dst = dst
        self._data = b''
        self._packet = Ether()/LLC()/Raw()

    def __repr__(self) -> str:
        return f'MkeTelegram{self.src, self.dst}'

    @property
    def packet(self):
        self.collect_title()
        self.collect_llc()
        self._packet = self._eth_title/self._llc/self._data
        return self._packet
    
    @property
    def data(self):
        return self._data

    @property
    def src(self):
        return self._src
    
    @src.setter
    def src(self, value):
        self._src = value
        self.collect_title()

    @property
    def dst(self):
        return self._dst
    
    @dst.setter
    def dst(self, value):
        self._dst = value
        self.collect_title()
        

    def subscribe(self, num):
        """подписка на телеграмму"""
        self.collect_data(num, 'E')
        

    def unsubscribe(self, num):
        """отписка от телеграммы"""
        self.collect_data(num, 'A')
        

    
    def collect_title(self):
        """собираем заголовок пакета (Ether)"""
        PREFIX = ['2']
        src=split_by_two(self.src)
        dst = split_by_two(self.dst)
        while len(src) < 5:
            src = ['0'] + src
        while len(dst) < 5:
            dst = ['0'] + dst
        src, dst = ':'.join(PREFIX + src), ':'.join(PREFIX + dst)
        self._eth_title = Ether(src=src,dst=dst,type=len(self.data))
    

    def collect_llc(self):
        self._llc = LLC(dsap=80, ssap=80, ctrl=103)


    def collect_data(self, num, param):
        pblnr = b'\0\1'
        pblna = b'\0\x45'
        fp = stb('PCAT')
        data = stb(f', MKS , {num}   , ')
        code = stb('ZD')
        param = stb(f', {param};')
        # после ef - идет длина LG
        telegram = b'\xc1' + pblnr + pblna + code + data + fp + param + b'\0\0\4\0A1\0\4'
        self._data = b'\xef' + itb(len(telegram)) + telegram


def itb(num: int) -> bytes:
    """преобразует int в bytes"""
    return bytes([num])

def split_by_two(what=str|int) -> list:
    what = str(what)[::-1]
    return [i[::-1] for i in [what[i:i+2] for i in range(0, len(what), 2)][::-1]]


def ether_title(source, dest, type) -> Ether:
    """собираем заголовок пакета (Ether)"""
    PREFIX = ['2']
    src=split_by_two(source)
    dst = split_by_two(dest)
    while len(src) < 5:
        src = ['0'] + src
    while len(dst) < 5:
        dst = ['0'] + dst
    src, dst = ':'.join(PREFIX + src), ':'.join(PREFIX + dst)
    result = Ether(src=src,dst=dst,type=type)
    return result

def subscribe_telegram_mks(abonent, nr_telegram):
    # type - в конечном итоге обновим на длину телеграммы
    title = ether_title(source=MY_ADDRESS, dest=abonent, type=0)
    llc = LLC(dsap=80, ssap=80, ctrl=103)
    pblnr = b'\x00\x01'
    pblna = b'\x00\x45'
    data = b'EZD, MKS , 7   , PCAT, E;\x00\x00\x00\x00A1\x00\x00'
    packet = title/llc/data
    return packet


def serialize_telegrams(telegram):
    ...


def my_sniffer():
    capture = sniff(count=1)
    for packet in capture:
        if Raw in packet:
            print(list(bytes(packet[Raw])))

    # a = rdpcap('traff\\119-mks6,7,8..0-1.pcapng')
    # for num, packet in enumerate(a):
    #     if num == 237:
    #         print(num, list(raw(packet)))
    #         dsap = get_dsap(packet)
    #         print(dsap)


def get_dsap(packet):
    packet = list(bytes(packet))
    dsap = int(''.join([str(i) for i in packet[1:6] if i]))
    ssap = int(''.join([str(i) for i in packet[7:12] if i]))
    return dsap, ssap


def main():
    # print(make_mke(abonent=111, nr_telegram=5))
    # mke_ether_title = ether_title(source=MY_ADDRESS, dest=111)
    # hexdump(subscribe_telegram_mks(113, 3))

    # mke = MkeTelegram(src=MY_ADDRESS)
    # mke.dst = 113
    # print(mke)
    # mke.subscribe(4)
    # print(hexdump(mke.packet))
    # mke.unsubscribe(4)
    # print(hexdump(mke.packet))
    
    my_sniffer()
    

if __name__ == '__main__':
    main()