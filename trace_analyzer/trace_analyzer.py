import os
import argparse as Arg
from collections import Counter

try :
    from scapy.utils import rdpcap
    from scapy.utils import hexdump
    from scapy.all import PcapReader
    from scapy.all import raw
    from scapy.sessions import IPSession
    from scapy.sessions import TCPSession
    from scapy.all import sniff
except :
    print("Error! Install 'scapy' ")


# READ FROM TERMINAL FLAG
def insert_flag() :
    parser = Arg.ArgumentParser(description="ARGUMENT FOR THE SEARCH OF PCAP FILE")
    parser.add_argument('-f',
                        '--file',
                        type=str,
                        help='Enter the path to the file')
    args = parser.parse_args()
    return args

#custum action function
def custom_action(pkt):
    key = tuple(sorted([pkt[0][1].src, pkt[0][1].dst]))
    pkt_counts = Counter()
    pkt_counts.update([key])
    return f"Packet #{sum(pkt_counts.values())}: {pkt[0][1].src} ==> {pkt[0][1].dst}"

# FUNCTION THAT READ FILE PCAP
def read_pcap(str_path) :
    try :
        a = rdpcap(str_path)
        return a
    except :
        print("Error! Can't read pcpap file")


# GRAPHICAL DUMPS don't work
def graphical_dumps(pkts) :
    pkts[423].pdfdump(layer_shift=1)


# HEXADECIMAL DUMP
def hexadecimal_dump(pkt) :
    hex = hexdump(pkt)
    print(hex)


# SNIFF IP
def sniff_IP(file_path):
    from scapy.layers.tls.session import TLSSession
    print(sniff(offline=file_path, session=TLSSession, prn=lambda x:x.summary()))


def main() :
    file_path = insert_flag().file
    print("Welcome to PCAP_Analyzer script\n\n\n")
    print(file_path)

    pkts = read_pcap(file_path)
    print(pkts)

    sniff_IP(file_path)

    # for pkt in pkts:
    # print(hexadecimal_dump(pkt))


# Press the green button in the gutter to run the script.
if __name__ == '__main__' :
    main()
