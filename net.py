#!/usr/bin/python

import time, math
# import pcap

def send_eth(ethernet_packet, payload):
	pack(ethernet_packet + payload)
	# sniffer.sendpacket(pack(ethernet_packet + payload))
	pass

def pack(byte_seq):
	s = b''.join(map(chr,byte_seq))
	return s

def check_back(adr, what):
	for ts, pkt in sniffer:
		if pkt.find(pack(adr)) == 0 and pkt.find(pack(what)) >= 0:
			strpkt = "".join("{:02x}".format(ord(c)) for c in pkt)
			return strpkt

def type_of_msg(msg):
	typ = [len(msg)]
	if len(typ) == 1:
		typ = [0x0] + typ
	while len(typ + msg) < 48:
		msg = msg + [0x88]
	return typ + msg

def connect_ps():
	dst = [0x02, 0x00, 0x00, 0x00, int(str(stoika)[:1]), int(str(stoika)[1:])]
	ethr = dst + src
	msg = [0x50, 0x50, 0x67]
	send_eth(ethr,type_of_msg(msg))
	print (check_back(src, [0x50, 0x51]))

def connect_module(mod):
	dst = [0x02, 0x00, 0x00, 0x00, int(str(stoika)[:1]), int(str(stoika)[1:])]
	ethr = dst + src
	msg = [0xc1, 0x00, 0x06, 0x00, 0x53, 0x45, 0x03, int(str(mod)), 0x80, 0x00, 0x14, 0x54, 0x52, 0x00, 0x04]
	msg = [0x50, 0x50, 0xe7, 0xef] + [len(msg)] + msg
	send_eth(ethr,type_of_msg(msg))
	print (check_back(src, [0x50, 0x51]))
	print (check_back(src, [0x50, 0x50]))
	msg = [0x50, 0x51, 0x67, 0x20]

def check_imitations():
	dst = [0x02, 0x00, 0x00, 0x00, int(str(stoika)[:1]), int(str(stoika)[1:])]
	ethr = dst + src
	msg = [0xc1, 0x00, 0x06, 0x00, 0x53, 0x42, 0x0c, 0x0f, 0x10, 0x00, 0x01, 0x01, 0x06, 0x11, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x54, 0x52, 0x00, 0x04]
	msg = [0x50, 0x50, 0x67, 0xef] + [len(msg)] + msg
	send_eth(ethr, type_of_msg(msg))
	print (check_back(src, [0x50, 0x51]))
	print (check_back(src, [0x50, 0x50]))
	msg = [0x50, 0x51, 0xe7, 0x20]
	send_eth(ethr, type_of_msg(msg))

def disconnect():
	dst = [0x02, 0x00, 0x00, 0x00, int(str(stoika)[:1]), int(str(stoika)[1:])]
	ethr = dst + src
	msg = [0xc1, 0x00, 0x06, 0x00, 0x53, 0x47, 0x01, 0x00, 0x22, 0x54, 0x52, 0x00, 0x04]
	msg = [0x50, 0x50, 0xe7, 0xef] + [len(msg)] + msg
	send_eth(ethr,type_of_msg(msg))
	print (check_back(src, [0x50, 0x51]))
	print (check_back(dst, [0x54, 0x52]))
	msg = [0x50, 0x51, 0x67, 0x20]
	send_eth(ethr, type_of_msg(msg))

def do_master(modl):
	dst = [0x02, 0x00, 0x00, 0x00, int(str(stoika)[:1]), int(str(stoika)[1:])]
	ethr = dst + src
	if len(str(modl)) < 3:
		msg = [0xc1, 0x00, 0x06, 0x00, 0x53, 0x42, 0x0e, 0x0f, 0xe3, 0x00, 0x01, 0x01, 0x08, 0x0d, 0x00]  + [int(modl)] + [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2b, 0x54, 0x52, 0x00, 0x04]
	else:
		msg = [0xc1, 0x00, 0x06, 0x00, 0x53, 0x42, 0x0e, 0x0f, 0xe3, 0x00, 0x01, 0x01, 0x08, 0x0d] + [int(str(modl)[:1]), int(str(modl)[1:])] + [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2b, 0x54, 0x52, 0x00, 0x04]
	msg = [0x50, 0x50, 0xe7, 0xef] + [len(msg)] + msg
	send_eth(ethr, type_of_msg(msg))

def read_analog(sq_bytes):
    # Extracting parts of the input bytes
    poz = float(int(str(sq_bytes)[0:2], 16))  # Extracting first two characters and converting to decimal
    grup = float(int(str(sq_bytes)[4:6], 16))  # Extracting characters 5 and 6 and converting to decimal
    dob = float(int(str(sq_bytes)[6:], 16))  # Extracting characters from position 7 to the end and converting to decimal

    # Calculating the analog value
    analog_value = grup * (2 ** (poz - 7)) + (dob / 128) * 2 ** (poz - 8)
    return analog_value

def write_analog(znach):
	poz = 7
	dob = 0
	ish = float(znach)
	while znach < 64:
		znach = znach*2
		poz -= 1
	while znach > 128:
		znach = znach / 2
		poz += 1
	znach = math.floor(znach)
	osn_dob = (1.0 / (2**(8 - poz))) / 128
	dob = (ish - znach / (2**(7 - poz)))
	dob = round(dob / osn_dob,0)
	text = map(int,[poz, 0x00, znach, dob])
	return text

def str_marker_2_hex(marker):
	module_type = '1717'
	marker = marker.split(',')
	if marker[0] == 'm':
		marker[1] = int(marker[1])
		marker[2] = int(marker[2])
		if marker[2] < 1 or marker[2] > 16:
			return None
		if 0 <= int(marker[1]) < 96:
			popr = 64
			move_group = 0
		elif 100 <= int(marker[1]) <= 149:
			popr = 70
			move_group =- 100
		elif 150 <= int(marker[1]) <= 159:
			popr = 76
			move_group =- 138
		elif 400 <= int(marker[1]) <= 403:
			popr = 73
			move_group =- 398
		elif 600 <= int(marker[1]) <= 603:
			popr = 73
			move_group =- 594
		elif 860 <= int(marker[1]) <= 869:
			popr = 74
			move_group =- 858
		elif 890 <= int(marker[1]) <= 891:
			popr = 74
			move_group =- 878
		elif 899 <= int(marker[1]) <= 903:
			popr = 74
			move_group =- 885
		elif 920 <= int(marker[1]) <= 924:
			popr = 75
			move_group =- 917
		elif 940 <= int(marker[1]) <= 944:
			popr = 75
			move_group =- 932
		elif 970 <= int(marker[1]) <= 974:
			popr = 75
			move_group =- 957
		marker[1] += move_group
		group = popr + math.floor(marker[1] / 16)
		poz = marker[2] + 16*(marker[1] % 16)
		return ([hex(int(poz)), hex(int(group))])
	elif marker[0] == 't':
		marker[1] = int(marker[1])
		if 1 <= marker[1] <= 32:
			poz = 48 + (marker[1])
			group = 76
			return ([hex(int(poz)), hex(int(group))])
	elif marker[0] == 'e':
		marker[2] = int(marker[2])
		if marker[1] == 's' and 1 <= marker[2] <= 71:
			group = 76
			poz = 80 + (marker[2])
			return ([hex(int(poz)), hex(int(group))])
	elif marker[0] == 'a':
		marker[2] = int(marker[2])
		if marker[1] == 's' and 1 <= marker[2] <= 41:
			group = 76
			poz = 151 + (marker[2])
			return ([hex(int(poz)), hex(int(group))])

def hex_2_str_marker(bytes):
    poz = int(str(bytes[0]))
    group = int(str(bytes[1]))
    group = (group - 64) * 16 + math.floor(poz / 16)
    poz = poz % 16
    if poz == 0:
        poz = 16
        group -= 1

    prefix = 'm'
    if 0 <= group <= 95:
        marker = [prefix, str(group), str(poz)]
    elif 100 <= group + 4 <= 149:
        marker = [prefix, str(group + 4), str(poz)]
    elif 400 <= group + 254 <= 403:
        marker = [prefix, str(group + 254), str(poz)]
    elif 600 <= group + 450 <= 603:
        marker = [prefix, str(group + 450), str(poz)]
    elif 860 <= group + 706 <= 891:
        marker = [prefix, str(group + 706), str(poz)]
    elif 899 <= group + 733 <= 903:
        marker = [prefix, str(group + 733), str(poz)]
    elif 920 <= group + 749 <= 924:
        marker = [prefix, str(group + 749), str(poz)]
    elif 940 <= group + 764 <= 944:
        marker = [prefix, str(group + 764), str(poz)]
    elif 970 <= group + 789 <= 974:
        marker = [prefix, str(group + 789), str(poz)]
    elif 195 <= group <= 196:
        prefix = 't'
        marker = [prefix, str((group - 195) * 16 + poz)]
    elif 197 <= group <= 200:
        prefix = 'e,s'
        marker = [prefix, str((group - 197) * 16 + poz)]
    elif group == 201 and poz >= 8:
        prefix = 'a,s'
        marker = [prefix, str((group - 201) * 16 + poz - 7)]
    elif 202 <= group <= 203:
        prefix = 'a,s'
        marker = [prefix, str((group - 202) * 16 + poz + 9)]
    elif 204 <= group <= 213:
        marker = [prefix, str(group - 54), str(poz)]
    return ','.join(marker)

def get_marker_from_packets(packet):
	marker = []
	counts = int(packet[74:76],16)
	itog = []
	for i in range (0,counts):
		marker = marker + [(packet[72 + i*4:74 + i*4], packet[78 + i*4:80 + i*4])]
	for i in marker:
		itog = itog + [hex_2_str_marker((int('0x' + i[0],16), int('0x' + i[1],16)))]
	return itog

def read_marker_val(bytes):
	about_markers = {}
	bytes = bytes[72:]
	kolvo = int(bytes[:2],16)
	max_znach = int(bytes[4:8],16)
	neimit = int(bytes[8:12],16)
	ravn_edin = int(bytes[12:16],16)
	imit_edin = int(bytes[16:20],16)
	nezaimit = int(bytes[20:24],16)
	#print (kolvo, max_znach, neimit, ravn_edin,imit_edin,nezaimit)
	i = kolvo - 1
	while i >= 0:
		about_markers.update({i:{}})
		#print (i, neimit - 2**i, ravn_edin - 2**i)
		if imit_edin - 2**i >= 0:
			imit_edin -= 2**i
			about_markers[i]['imit_value'] = [1]
		else:
			about_markers[i]['imit_value'] = [0]
		if ravn_edin - 2**i >= 0:
			ravn_edin -= 2**i
			about_markers[i]['value'] = [1]
		else:
			about_markers[i]['value']=[0]
		if neimit - 2**i >= 0:
			neimit -= 2**i
			about_markers[i]['can_imit'] = [0]
		else:
			about_markers[i]['can_imit'] = [1]
		if nezaimit - 2**i >= 0:
			nezaimit -= 2**i
			about_markers[i]['imit'] = [0]
		else:
			about_markers[i]['imit'] = [1]
		i -= 1
	#print (about_markers)
	#for i in about_markers:
	#	print i,about_markers[i]
	return about_markers
	
def read_markers(marker):
	dst = [0x02, 0x00, 0x00, 0x00, int(str(stoika)[:1]), int(str(stoika)[1:])]
	ethr = dst + src
	puts = []
	marker = marker.split(' ')
	for i in marker:
		puts = puts + [int(str_marker_2_hex(i)[0],16), int(str_marker_2_hex(i)[1],16)]
	dlin = int(len(puts) / 2)
	msg = [0x00]*(dlin*2 + 2)
	msg[1] = dlin
	for i in range(0, dlin):
		msg[i*2] = puts[i*2]
		msg[i*2 + 3] = puts[i*2 + 1]
	msg = [0x12, 0x00, 0xff, 0x00] + msg
	msg = [0x0f, 0x16, 0x00, 0x01, 0x01] + [len(msg)] + msg  #0x16 - ?
	msg = [0xc1, 0x00, 0x06, 0x00, 0x53, 0x42, len(msg)] + msg + [0x00, 0x28, 0x54, 0x52, 0x00, 0x04]
	msg = [0x50, 0x50, 0xe7, 0xef] + [len(msg)] + msg
	print (msg)
	send_eth(ethr,type_of_msg(msg))
	print (check_back(dst, [0x50, 0x50]))

if __name__ == '__main__':
	global sniffer, src, stoika
	# sniffer = pcap.pcap(name=None, promisc=True, immediate=True)
	sniffer = 1
	src = [0x02, 0x00, 0x00, 0x00, 0x01, 0x23]
	stoika = 639
	connect_ps()
	connect_module(21)
	# m = 'm,71,10'
	# read_markers(m)
	print( get_marker_from_packets ('02000000061102000000012300225050e7ef1dc10006005342100f160001010a1200ff002b022c470047003054520004888888888888888888888888'))
	sost_mark = read_marker_val('02000000061102000000012300225050e7ef1dc10006005342100f160001010a1200ff002b022c470047003054520004888888888888888888888888')
	print(sost_mark)
 	#for i in sost_mark:
	#	print i, sost_mark[i]
