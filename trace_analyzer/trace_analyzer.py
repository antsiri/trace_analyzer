import base64import reimport datetimeimport globimport argparseimport osimport anglerfrom struct import *try:    from scapy.all import *    from scapy.layers import httpexcept:    print("Try '# pip instll scapy")def __parse_pcap__(directory, out=None):    bind_layers(TCP, http.HTTP, sport=3148)    bind_layers(TCP, http.HTTP, dport=3148)    for pcap_file in glob("%s%s" % (directory, "*.pcap")):        print("File founded: %s" % (pcap_file))        pcap = rdpcap(pcap_file)        flows = pcap.filter(lambda: http.HTTPResponse in s)        html_begin_found = False        html_end_found = False        html = ""        for flow in flows:            payload = flow[http.HTTP].payload            if not html_begin_found:                token_re = re.compile(                    r'Content-Type:\s+text/html', re.IGNORECASE)                m = token_re.search(str(payload))                if(m is None):                    continue                else:                    html_begin_found = True            else:                token_re = re.compile(r'</html', re.IGNORECASE)                m = token_re.search(str(payload))                if(m is not None):                    html_end_found = True            if (html_begin_found):                tmp_html = str(payload)                if(tmp_html is not None):                    #tmp_html = __extract_html__(tmp_html)                    if(tmp_html is not None):                        html += tmp_html            if (html_begin_found and html_end_found):                html_end_found = False                html_begin_found = False                if(html is not None):                    if(out is None):                        print(html)                    else:                        filename = os.path.basename(pcap_file)                        if(os.path.exists("%s-%s.html" % (out, filename))):                            i = 0                            while(os.path.exists("%s//%s-%s.html" % (out, filename, i))):                                i = i+1                            filename = "%s-%s" % (filename, i)                        fd = open("%s/%s.html" % (out, filename), "wb")                        fd.write(html)                        fd.close()            html = ""    returndef main():    parser = argparse.ArgumentParser(        description='Parse PCAP files and search for Angler traces')    parser.add_argument('-dir', '--directory', help='Directory where to search for PCAP to analyse.')    #parser.add_argument('-out', '--output_directory',                        #help='Directory where to wrote all information extracted (by default stdout)')    args = parser.parse_args()      # Check if an output directory is set    directory = None    if (args.output_directory):        directory = os.path.dirname(args.output_directory)        if not (os.path.exists(directory)):            os.makedirs(directory)        if args.directory:            __parse_pcap__(args.directory, directory)        else:            print ("You need to specify a directory where to search for pcap file")#if __name__ == "__main__":