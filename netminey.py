#!/usr/bin/env python
# encoding: utf-8


import sys
import argparse
import logging
import pprint
import base64
import binascii
import fleep 
import hashlib
import tqdm
import random
import hexdump
import shutil
from termcolor import colored, cprint
from scapy.all import *
from scapy.layers import http

BUF_SIZE = 65536  #needed for file hashing, reduced load in memory, reads in 64kb chunks

__authors__ = "joelgun"
__copyright__ = ""
__credits__ = ["joelgun"]
__license__ = "MIT"
__date__ = "2019"
__version__ = "1.0"
__maintainer__ = "joelgun"
__email__ = "twitter://@joelgun"
__status__ = "production"
__description__ = "netminey - light weight pcap assessment / analysis tool"

logo_string = """
                                            
                #       #              
        ##  ### ### ###     ##  ### # # 
        # # ##   #  ###  #  # # ##  ### 
        # # ###  ## # #  ## # # ###   # 
                                    ### 
        @joelgun - v1.0
    """


conf.contribs["http"]["auto_compression"] = True

load_layer("http")

def load_pcap(inputfile):
    print('\n') 
    print(f" [ xxx ] Load PCAP.....")
    try: 
        packets = sniff(offline=inputfile, session=TCPSession)
        print(f" [ >> ] {inputfile} loaded")
        print('\n')  
    except:
        print(f" File: {inputfile} couldn't be loaded! ")
        sys.exit
    return packets

def load_filtered_pcap(inputfile, filter_values):
    print('\n') 
    print(f" [ xxx ] Load PCAP and filter the packets.....")
   
    filter_vals = ''.join(filter_values)
  
    try:
        packets = sniff(offline=inputfile,filter=filter_vals, session=TCPSession)
        print(f" [ >> ] {inputfile} loaded")
        print('\n') 
    except:
        print(f" File: {inputfile} couldn't be loaded! ")
        sys.exit
    return packets
"""
def load_netflow_data(inputfile):
    try:
        packets = sniff(inputfile, session=NetflowSession)
    except:
        print(f" File: {inputfile} couldn't be loaded! ")   
    return packets
"""
def packets_summary(packets, inputfile):
    print('\n') 
    print(f" [ xxx ] Parsing PCAP.....")
    print('\n')  
    print(f" Inputfile: {inputfile}")
    print(f" Summary: {packets}")

def show_http(packets):
    print('\n') 
    print(f" [ xxx ] Parsing HTTP connections.....")
    print('\n')  
    for packet in packets:
        if packet.haslayer("TCP"):
            load_layer("http")
           
            if packet.haslayer('HTTPRequest'):
                print('\n')
                print(f":::: Communication: {packet[IP].src} <--> {packet[IP].dst} :::: ")
                print(f" >> Request:  ")
                print(f"        Source: {packet[IP].src}")
                print(f"        Destination: {packet[IP].dst}")
                
                http_req= packet.getlayer('HTTPRequest').fields
                ip_layer = packet.getlayer('IP').fields

                for key in http_req:
                    if key == "Unknown_Headers":
                        print(f"            {key} : {http_req[key]}")
                    else:
                        print(f"            {key} : {http_req[key].decode('utf-8')}")
                    
            load_layer("http")
            if packet.haslayer("HTTPResponse"):
                http_resp= packet.getlayer('HTTPResponse').fields
                print(" > Response: ")

                print(f"        Source: {packet[IP].src}")
                print(f"        Destination: {packet[IP].dst}")
                for key in http_resp:
                    if key == "Unknown_Headers":
                        print(f"            {key} : {http_resp[key]}")
                    else:
                        print(f"            {key} : {http_resp[key].decode('utf-8')}")
          

def hash_output(parsed_output_dir):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()

    with open("./"+parsed_output_dir+"/temp_file", 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
   
    print("         MD5: {0}".format(md5.hexdigest()))
    print("         SHA1: {0}".format(sha1.hexdigest()))   
    return sha1.hexdigest()

def show_http_extract_payload(packets, parsed_output_dir):
    print('\n') 
    print(f" [ xxx ] Parsing HTTP connections and extracting payloads.....")
    print('\n')  
    for packet in packets:
        load_layer("http")
        
        if packet.haslayer('HTTPRequest'):
            
            print('\n')
            print(f":::: Communication: {packet[IP].src} <--> {packet[IP].dst} :::: ")
            print(f" >> Request:  ")
            print(f"        Source: {packet[IP].src}")
            print(f"        Destination: {packet[IP].dst}")
            
            http_req= packet.getlayer('HTTPRequest').fields
            ip_layer = packet.getlayer('IP').fields

            for key in http_req:
                if key == "Unknown_Headers":
                    print(f"            {key} : {http_req[key]}")
                else:
                    print(f"            {key} : {http_req[key].decode('utf-8')}")
            if http_req['Path']:   
                urlpath = http_req['Path']
            else:
                urlpath = "no_value"
        load_layer("http")
        if packet.haslayer("HTTPResponse"):
            http_resp= packet.getlayer('HTTPResponse').fields
            print("   >> Response: ")

            print(f"        Source: {packet[IP].src}")
            print(f"        Destination: {packet[IP].dst}")
            for key in http_resp:
                if key == "Unknown_Headers":
                    print(f"            {key} : {http_resp[key]}")
                else:
                    print(f"            {key} : {http_resp[key].decode('utf-8')}")
            if http_req['Path']:   
                urlpath = http_req['Path']
            else:
                urlpath = "no_value"

            if packet.haslayer('Raw'):
                filename =  str(urlpath)[ str(urlpath).rfind("/")+1:]
                filename = filename.replace("'", '')

                extracted_file_path = "./"+parsed_output_dir+"/"+packet[IP].src+"-to-"+packet[IP].dst
                if not os.path.exists(extracted_file_path):
                    os.mkdir(extracted_file_path)
                    
                with open(extracted_file_path+"/temp_file", "wb") as f:
                    f.write(packet.getlayer('Raw').load)
                    f.close()

                with open(extracted_file_path+"/temp_file", "rb") as f:    
                    file_data = f.read(128)
                    fleep_info = fleep.get(file_data)
                    print('\n')
                    print(f"   >> Attachment Information:  ")
                    print(f"         Attachment: {filename}")
                    hashvalue = hash_output(extracted_file_path)
                    print('\n')
                    hexdump(file_data)
                    print('\n')
                    
                    if len(fleep_info.type):
                        print(f"        Possible type:       {fleep_info.type} ")  # prints ['raster-image']
                        print(f"        Possible extension:  {fleep_info.extension} ")  # prints ['png']
                        print(f"        Possible mime type:  {fleep_info.mime} ")  # prints ['image/png']

                    f.close()
                  
                   
                if len(fleep_info.extension):
                    os.rename(extracted_file_path+"/temp_file", extracted_file_path+"/"+filename+"-"+hashvalue+"."+str(fleep_info.extension[0]))
                    print('\n')
                    print(f"File saved:  "+ extracted_file_path+"/"+filename+"-"+hashvalue+"."+str(fleep_info.extension[0]))
                  
                    print("******")  
                else:
                    os.rename(extracted_file_path+"/temp_file", extracted_file_path+"/"+filename+"-"+hashvalue)   
                    print('\n')  
                    print(f"File saved:  "+ extracted_file_path+"/"+filename+"-"+hashvalue) 
                    
                    print("******")              
            else:
                print(f" Packet has 0 bytes in HTTPResponse field. ")   
            print('\n')
            ip_layer = packet.getlayer('IP').fields

def show_ports(packets,mode):
    print('\n') 
    print(f" [ xxx ] Parsing sniffed Connections.....")
    print('\n')  

    if mode == 'all':
        protocol = str()
        for packet in packets:
            if UDP in packet or TCP in packet :
                if packet[IP].proto == 6:
                    protocol = "TCP"
                elif packet[IP].proto == 17:
                    protocol = "UDP"
                else:
                    protocol = "Protocolnumber: "+str(packet[IP].proto)+" idk, google it. "  
                print(f" {protocol} >> {datetime.fromtimestamp(packet.time).strftime(' %B  %d, %Y')} {packet[IP].src}:{packet.sport}        == to ==> {packet[IP].dst}:{packet.dport}")    
    
    elif mode == 'overview':
        connection_table = dict()
        counter = 1
        for packet in packets:
            
            if UDP in packet or TCP in packet :
                if packet[IP].proto == 6:
                    protocol = "TCP"
                elif packet[IP].proto == 17:
                    protocol = "UDP"
                else:
                    protocol = "Protocolnumber: "+str(packet[IP].proto)+" idk, google it. "  

                current_package_time = datetime.fromtimestamp(packet.time).strftime(' %B  %d, %Y')
                current_conn = protocol+";"+current_package_time+";"+packet[IP].src+":"+str(packet.sport)+";"+packet[IP].dst+":"+str(packet.dport)

                if current_conn in connection_table:
                    connection_table[current_conn] += counter
                else:
                    connection_table[current_conn] = counter
        
        print(f" >> Overview connection: ")
        for k,v in connection_table.items():
            conns = k.split(";")
            print(f" {conns[0]} >> {conns[1]} -- from: {conns[2] }   == to ==> {conns[3]} : amount: {v}")
    
    else:
        pass

def create_folders(inputfile_name):
    print('\n') 
    print(f" [ xxx ] Creating folders for the extracted payloads.....")
    print('\n')  

    path = os.getcwd()
    print ("The current working directory is: %s" % path)

    path = inputfile_name+"_parsed_output"

    try:
        if os.path.exists(path):
            shutil.rmtree(path)
        os.mkdir(path)
    except OSError:
        print ("Creation of the directory %s failed" % path)
        time.sleep(1)
    else:
        print ("Successfully created the directory: %s " % path)
    return path

def show_dns(packets):
    print('\n') 
    print(f" [ xxx ] Parsing DNS queries.....")
    print('\n')  

    for packet in packets:
        if packet.haslayer("UDP"):
            if packet.haslayer(DNSRR):    
                for x in range(packet[DNS].ancount):
                    if packet[DNSRR][x].type == 16:
                        print(f"    Source: {packet[IP].dst}")
                        print(f"    DNS Server: {packet[IP].src}")
                        print(f'    Resource Name: {packet[DNSRR][x].rrname.decode("utf-8")[:-1]}')
                        print(f'    TXT Record: {packet[DNSRR][x].rdata}')
                                    
                    elif packet[DNSRR][x].type == 1:    
                        if isinstance(packet[DNSRR][x].rdata, bytes) != True:
                            print(f"    Source: {packet[IP].dst}")
                            print(f"    DNS Server: {packet[IP].src}")
                            print(f"    Queried IP: {packet[DNSRR][x].rdata}")
                            print(f'    Queried domain: {packet[DNSRR][x].rrname.decode("utf-8")[:-1]}')    
                    else:
                        continue
                    print('\n')    
        else:
            continue 
    print('\n') 

def progressbar_unique():
    for i in tqdm.trange(int(1e2), miniters=int(1e1), ascii=True,
                     desc="1337", dynamic_ncols=True):
        time.sleep(0.01)
   
def show_logo():
    print(logo_string)
    print('\n')
    pass

def main():
    
    formatter_class = argparse.RawDescriptionHelpFormatter
    parser = argparse.ArgumentParser(description=module,
                                     formatter_class=formatter_class)
   
    parser.add_argument("-http", "--http", action='store_true',
                        help="Parses PCAP for HTTP connections .")
    parser.add_argument("-ep", "--extract", action='store_true',
                        help="Parses PCAP for HTTP connections and extract payloads .")
    parser.add_argument("-all", "--all", action='store_true',
                        help="Parses PCAP for DNS, HTTP connections, extracts payloads and shows a connection overview. ")
    parser.add_argument("-d", "--dns", action='store_true',
                        help="Parses PCAP for DNS data from pcap") 
    parser.add_argument("-co", "--conns", type=str, choices=['overview', 'all'],
                        help="Prints all communication incl. ports, choose between overview or all. ") 
    parser.add_argument("-s", "--summary", action='store_true',
                        help="Summary over all connections from pcap.")   
    parser.add_argument("-ft", "--filter", nargs="+",
                        help='Pre filter the pcap while loading it in memory. i.e. --filter "host 10.1.1.1". BPF syntax  https://biot.com/capstats/bpf.html' )                            
    parser.add_argument("--version", "--version" , action="version",
                        version="%(prog)s {}".format(__version__))
    parser.add_argument("-in", "--inputfile", required=True, metavar="inputfile", help="PCAP file you want to analyze.")
  
    args = parser.parse_args()

    if args.filter: 
        packets = load_filtered_pcap(args.inputfile,args.filter)
    else:
        packets = load_pcap(args.inputfile)

    if  args.dns:
        progressbar_unique()
        show_dns(packets)

    elif args.http:
        progressbar_unique()
        show_http(packets)

    elif args.extract:
        progressbar_unique()
        parsed_output_dir = create_folders(args.inputfile)
        show_http_extract_payload(packets,parsed_output_dir)

    elif args.summary:
        progressbar_unique()
        packets_summary(packets, args.inputfile)

    elif args.all:
        progressbar_unique()
        packets_summary(packets, args.inputfile)
        show_dns(packets)
        show_ports(packets,"overview")
        parsed_output_dir = create_folders(args.inputfile)
        show_http_extract_payload(packets,parsed_output_dir)

    elif args.conns:
        progressbar_unique()
        show_ports(packets, args.conns)
    else: 
        progressbar_unique()
        packets_summary(packets, args.inputfile)
        print('\n')
        print(f"No arguments - try with python3 netminey.py -h")
               

if __name__ == "__main__":
    show_logo()
    main()
