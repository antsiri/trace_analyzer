import os
import argparse as Arg
import time
from collections import Counter
from io import StringIO
import csv
import pyshark
from lxml.builder import basestring

try :
    from scapy.all import *
    from scapy.utils import rdpcap, hexdump, RawPcapReader
    from scapy.all import PcapReader, raw, sniff
    from scapy.sessions import IPSession, TCPSession
    from scapy.layers.dns import DNS, DNSRR, DNSQR
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.inet import IP, UDP, TCP
except :
    print("Error! Install 'scapy' ")


#**************************************************************************
# READ FROM TERMINAL FLAG
def insert_flag() :
    parser = Arg.ArgumentParser(description="ARGUMENT FOR THE SEARCH OF PCAP FILE")
    parser.add_argument('-f',
                        '--file',
                        type=str,
                        help='Enter the path to the file')
    args = parser.parse_args()
    return args

#**************************************************************************
#PCAP INFO
def get_info(pkts):
    file = open("Info.txt", 'w')
    file.write("Info\n\n")

    pack = Ether()/IP()/TCP()/UDP()

    capture = StringIO()
    save_stdout = sys.stdout
    sys.stdout = capture
    pack.show()
    sys.stdout = save_stdout

    file.write(capture.getvalue())

    file.close()

#CONVERSATION
def conversation(pkts):
    with open('conversation.csv', 'w', newline='') as file:
        fcsv = csv.writer(file)
        fcsv.writerow(['src', 'dst'])
        for pkt in pkts:
            fcsv.writerow([pkt.src, pkt.dst])
    #with open('conversation.csv', 'w', newline='') as f:
     #   fcsv = csv.writer(f)
      #  fcsv.writerow(headers)
       # fcsv.writerow(rows)

#**************************************************************************
# custum action function
def custom_action(pkt) :
    key = tuple(sorted([pkt[0][1].src, pkt[0][1].dst]))
    pkt_counts = Counter()
    pkt_counts.update([key])
    return f"Packet #{sum(pkt_counts.values())}: {pkt[0][1].src} ==> {pkt[0][1].dst}"


#**************************************************************************
# FUNCTION THAT READ FILE PCAP
def read_pcap(str_path) :
    try :
        a = rdpcap(str_path)
        return a
    except :
        print("Error! Can't read pcpap file")


def dns_query(pkts) :
    file = open("DNSQuery.txt", 'w')
    file.write("DNSQuery\n\n")
    time.sleep(0.5)
    for pkt in pkts :
        if pkt.haslayer(DNS) :
            if pkt.qdcount > 0 and isinstance(pkt.qd, DNSQR) :
                name = pkt.qd.qname
            elif pkt.qdcount > 0 and isinstance(pkt.qd, DNSRR) :
                name = pkt.an.rdata
            else :
                continue

            file.write(str(name))
            file.write("\n")
    print("DNSQuery.txt created")
    file.close()


# GRAPHICAL DUMPS don't work
def graphical_dumps(pkts) :
    pkts[423].pdfdump(layer_shift=1)


# HEXADECIMAL DUMP
def hexadecimal_dump(pkt) :
    hex = hexdump(pkt)
    print(hex)


# ARP MONITOR
def arp_monitor(pkt) :
    if pkt[ARP].op == 1 :
        return f"Request: {pkt[ARP].psrc} was asking {pkt[ARP].pdst}"
    if pkt[ARP].op == 2 :
        return f"*Response: {pkt[ARP].hwsrc} has address {pkt[ARP].psrc}"


# SNIFF IP
def sniff_IP(file_path) :
    from scapy.layers.tls.session import TLSSession
    file = open("SNIFF_IP.txt", 'w')
    file.write("SNIFF_IP\n")
    file.write(str(sniff(offline=file_path, session=TLSSession, prn=lambda x : x.summary())))
    print("SNIFF_IP.txt created")
    file.close()


def sniff_arp(file_path) :
    sniff(offline=file_path, prn=arp_monitor, filter='arp')

def main() :
    file_path = insert_flag().file
    print("\n\n")
    print(" ____    ____     ____     ____    ____     ___        _   _____    ____   _____ ")
    print("|  _ \  |  _ \   / ___|   |  _ \  |  _ \   / _ \      | | | ____|  / ___| |_   _|")
    print("| |_) | | | | | | |       | |_) | | |_) | | | | |  _  | | |  _|   | |       | |  ")
    print("|  _ <  | |_| | | |___    |  __/  |  _ <  | |_| | | |_| | | |___  | |___    | |  ")
    print("|_| \_\ |____/   \____|   |_|     |_| \_\  \___/   \___/  |_____|  \____|   |_|  ")
    print("\n*******************************************************\n")
    print("by Filomena Vigliotti, Antonio Russo, Antonio Sirignano")
    print("\n*******************************************************\n")

    print("\n\nFile selected: ", file_path)

    pkts = read_pcap(file_path)

    if not pkts:
        print("Error! File empty or damaged")
    else:
        print("\nInfo:\n")
        get_info(pkts)
        print("Info.txt written...")
        print("\n*******************************************************\n")

        print("\nConversation:\n")
        conversation(pkts)
        print("Conversation.csv written...")
        print("\n*******************************************************\n")

        print("\nDNS Query:\n")
        dns_query(pkts)
        print("DNSQuery.txt written...")
        print("\n*******************************************************\n")

        print("\nSniff IP:\n")
        sniff_IP(file_path)
        print("Sniff.txt written...")
        print("\n*******************************************************\n")

        # for pkt in pkts:
        # print(hexadecimal_dump(pkt))

        print("Process completed")



# Press the green button in the gutter to run the script.
if __name__ == '__main__' :
    main()
