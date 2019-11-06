#!/usr/bin/env python3
import sys
from scapy.all import *
import codecs

if len(sys.argv) != 4:
	print("Bad format!")
	print("Instruction:")
	print("./listener [source_ip] [interface] [file]")
	sys.exit()

INTERFACE = sys.argv[2]
SNIFF_FILER = 'src host ' + sys.argv[1]
FILENAME = sys.argv[3]
DEFAULT_TEXT_FILE_LENGTH = 75075
DEFAULT_FILE_CHUNK_SIZE = 1440
DEFAULT_INITIAL_CODE = "YES"
DEFAULT_MESSAGE_INITIALS = codecs.encode(DEFAULT_INITIAL_CODE.encode(), "base64")

byte_msg = bytes()
msg_len_diff = DEFAULT_TEXT_FILE_LENGTH
file = open(FILENAME, "w+")

def packet_handler(pkt):
	global byte_msg
	global msg_len_diff
	if TCP in pkt and pkt[TCP].sport > 1024:
		payload = bytes(pkt[TCP].payload)
		if DEFAULT_MESSAGE_INITIALS in payload:
			if msg_len_diff > DEFAULT_FILE_CHUNK_SIZE:
				byte_msg += bytes(payload[-DEFAULT_FILE_CHUNK_SIZE:])
				msg_len_diff-=DEFAULT_FILE_CHUNK_SIZE
			else:
				byte_msg += bytes(payload[-msg_len_diff:])

def file_loader(pkt):
	global byte_msg
	if len(byte_msg) == DEFAULT_TEXT_FILE_LENGTH:
		normal_msg = codecs.decode(bytes(byte_msg), 'base64')
		normal_msg = normal_msg.decode()
		file.write(normal_msg)
		file.close()
		return True

sniff(
	iface=INTERFACE,
	store=False,
	prn=packet_handler,
	stop_filter=file_loader,
	filter=SNIFF_FILER
)


