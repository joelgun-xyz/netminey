# netminey

A Lightweight PCAP assessment tool based on python3 and the scapy library. 
Feel free to tweak / modify the code. 

## Getting Started

Clone the repo with 

```
git clone https://github.com/joelgun-xyz/netminey.git
```

### Prerequisites

This tool runs on Python3. 

### Installing

You need to install a couple of libs from the requirements.txt

```
fleep==1.0.1
tqdm==4.31.1
termcolor==1.1.0
scapy==2.4.3
hexdump==3.3
```

Change in the cloned project directory and run following command to install them all: 

```
pip3 install -r requirements.txt
```

## Usage

```
usage: netminey.py [-h] [-http] [-ep] [-all] [-d] [-co {overview,all}]
                   [-cv {icmp,tcp}] [-f [FIND]] [-su]
                   [-ft FILTER [FILTER ...]] [--version] -in inputfile

netminey.py

optional arguments:
  -h, --help            show this help message and exit
  -http, --http         Parses PCAP for HTTP connections .
  -ep, --extract        Parses PCAP for HTTP connections and extract payloads
                        .
  -all, --all           Parses PCAP for DNS, HTTP connections, extracts
                        payloads and shows a connection overview.
  -d, --dns             Parses PCAP for DNS data from pcap
  -co {overview,all}, --conns {overview,all}
                        Prints all communication incl. ports, choose between
                        overview or all.
  -cv {icmp}, --covertscan {icmp}
                        Scans for possible covert channel in ICMP packets.
  -f [FIND], --find [FIND]
                        Scans for credentials in default or custom text.
  -su, --summary        Summary over all connections from pcap.
  -ft FILTER [FILTER ...], --filter FILTER [FILTER ...]
                        Pre filter the pcap while loading it in memory. i.e.
                        --filter "host 10.1.1.1". BPF syntax
                        https://biot.com/capstats/bpf.html
  --version, --version  show program's version number and exit
  -in inputfile, --inputfile inputfile
                        PCAP file you want to analyze.
```

#### Set filter 

You can pre filter the PCAP while loading it into memory with the BPF filter syntax. For more information see here: https://biot.com/capstats/bpf.html

```
python3 netminey.py --filter "host 10.10.10.209" [flags you want to parse for; i.e. --http] [inputfile; -in test.pcap]
```

Output:

```
 [ xxx ] Load PCAP and filter the packets.....
reading from file 2018-04-11-traffic-analysis-exercise.pcap, link-type EN10MB (Ethernet)
 [ >> ] 2018-04-11-traffic-analysis-exercise.pcap loaded

.....
```

#### Parse for HTTP connections

```
python3 netminey.py --http -in 2018-04-11-traffic-analysis-exercise.pcap
```

Output:

```
[ xxx ] Load PCAP.....
 [ >> ] 2019-08-20-traffic-analysis-exercise.pcap loaded


1337: 100%|#################################################################################################################################################| 100/100 [00:01<00:00, 85.98it/s]


 [ xxx ] Parsing HTTP connections.....

:::: Communication: 10.8.20.101 <--> 63.239.233.90 :::: 
 >> Request:  
        Source: 10.8.20.101
        Destination: 63.239.233.90
            Connection : Close
            Host : www.msftncsi.com
            User_Agent : Microsoft NCSI
            Method : GET
            Path : /ncsi.txt
            Http_Version : HTTP/1.1
 > Response: 
        Source: 63.239.233.90
        Destination: 10.8.20.101
            Cache_Control : max-age=30, must-revalidate
            Connection : close
            Content_Length : 14
            Content_Type : text/plain
            Date : Tue, 20 Aug 2019 19:30:48 GMT
            Http_Version : HTTP/1.1
            Status_Code : 200
            Reason_Phrase : OK
.....
```

#### Parse for DNS connections

```
python3 netminey.py --dns -in dnstxt.pcap 
```

Output:

```
[ xxx ] Load PCAP.....
 [ >> ] 2019-08-20-traffic-analysis-exercise.pcap loaded


1337: 100%|#################################################################################################################################################| 100/100 [00:01<00:00, 83.01it/s]

 [ xxx ] Parsing DNS queries.....

    Source: 10.8.20.101
    DNS Server: 10.8.20.8
    Queried IP: 206.189.74.47
    Queried domain: idogoiania.com.br

.....
```

The script also parses queried TXT records:

```
.....

 Source: 192.168.43.10
    DNS Server: 9.9.9.9
    Resource Name: evildomain.tk
    TXT Record: [b'dGhpc2lzYWMyY29tbWFuZGZyb21hbmV2aWxoYWNrZXI=']

.....
```

#### Parse for HTTP connections and extract payloads

```
python3 netminey.py -ep -in dnstxt.pcap 
```

Output: 

```
 [ xxx ] Load PCAP.....
 [ >> ] 2019-08-20-traffic-analysis-exercise.pcap loaded


1337: 100%|#################################################################################################################################################| 100/100 [00:01<00:00, 84.06it/s]


 [ xxx ] Creating folders for the extracted payloads.....


The current working directory is: /Users/joelgun/Scripts/netminey
Successfully created the directory: 2019-08-20-traffic-analysis-exercise.pcap_parsed_output


 [ xxx ] Parsing HTTP connections and extracting payloads.....


:::: Communication: 10.8.20.101 <--> 185.183.98.232 :::: 
 >> Request:  
        Source: 10.8.20.101
        Destination: 185.183.98.232
            Cache_Control : no-cache
            Connection : Keep-Alive
            Host : 185.183.98.232
            Pragma : no-cache
            User_Agent : WinHTTP loader/1.0
            Method : GET
            Path : /samerton.png
            Http_Version : HTTP/1.1
   << Response: 
        Source: 185.183.98.232
        Destination: 10.8.20.101
            Accept_Ranges : bytes
            Connection : keep-alive
            Content_Length : 845312
            Content_Type : image/png
            Date : Tue, 20 Aug 2019 19:53:42 GMT
            ETag : "5d5c1cc2-ce600"
            Last_Modified : Tue, 20 Aug 2019 16:16:02 GMT
            Server : nginx/1.10.3
            Http_Version : HTTP/1.1
            Status_Code : 200
            Reason_Phrase : OK


   >> Attachment Information:  
         Attachment: samerton.png
         MD5: 7c96f51b36d5d2b747531713bc4c4b3d
         SHA1: 9b6e9c84e918dad5e2799912a6f971be01eb6f25


0000  4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00  MZ..............
0010  B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  ........@.......
0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0030  00 00 00 00 00 00 00 00 00 00 00 00 F0 00 00 00  ................
0040  0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68  ........!..L.!Th
0050  69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F  is program canno
0060  74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20  t be run in DOS 
0070  6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00  mode....$.......

        Possible type:       ['executable', 'system'] 
        Possible extension:  ['exe', 'dll', 'drv', 'sys', 'com'] 
        Possible mime type:  ['application/vnd.microsoft.portable-executable', 'application/x-msdownload'] 


File saved:  ./2019-08-20-traffic-analysis-exercise.pcap_parsed_output/185.183.98.232-to-10.8.20.101/samerton.png-9b6e9c84e918dad5e2799912a6f971be01eb6f25.exe
******
```

#### Show connection overview

**This flag is recommended to only use with the --filter flag. The output can be quiet large.**

Flag: -co overview 

```
python3 netminey.py -co overview -in susp_ports.pcap 
```

```
 [ xxx ] Load PCAP.....
 [ >> ] susp_ports.pcap loaded


1337: 100%|#################################################################################################################################################| 100/100 [00:01<00:00, 82.27it/s]


 [ xxx ] Parsing sniffed Connections.....


 >> Overview connection: 
 TCP >> Thursday, December  12, 2019 07:17:59 -- from: 192.168.43.10:49238   == to ==> 35.186.224.53:443 : amount: 6
 TCP >> Thursday, December  12, 2019 07:17:59 -- from: 35.186.224.53:443   == to ==> 192.168.43.10:49238 : amount: 6
 TCP >> Thursday, December  12, 2019 07:18:00 -- from: 192.168.43.10:49487   == to ==> 35.186.224.47:443 : amount: 2
 TCP >> Thursday, December  12, 2019 07:18:00 -- from: 35.186.224.47:443   == to ==> 192.168.43.10:49487 : amount: 1
 TCP >> Thursday, December  12, 2019 07:18:02 -- from: 192.168.43.10:49734   == to ==> 192.168.0.2:1337 : amount: 1
 TCP >> Thursday, December  12, 2019 07:18:03 -- from: 192.168.43.10:49734   == to ==> 192.168.0.2:1337 : amount: 1
 TCP >> Thursday, December  12, 2019 07:18:04 -- from: 192.168.43.10:49734   == to ==> 192.168.0.2:1337 : amount: 1
 TCP >> Thursday, December  12, 2019 07:18:05 -- from: 192.168.43.10:49734   == to ==> 192.168.0.2:1337 : amount: 1
 TCP >> Thursday, December  12, 2019 07:18:06 -- from: 192.168.43.10:49734   == to ==> 192.168.0.2:1337 : amount: 1
 TCP >> Thursday, December  12, 2019 07:18:07 -- from: 192.168.43.10:49734   == to ==> 192.168.0.2:1337 : amount: 1
 TCP >> Thursday, December  12, 2019 07:18:09 -- from: 192.168.43.10:63705   == to ==> 192.168.178.22:53 : amount: 1
 TCP >> Thursday, December  12, 2019 07:18:09 -- from: 192.168.43.10:49735   == to ==> 17.134.127.249:443 : amount: 3

.....
```


Flag: -co all

```
python3 netminey.py -co all -in susp_ports.pcap
```

```
[ xxx ] Load PCAP.....
 [ >> ] susp_ports.pcap loaded


1337: 100%|#################################################################################################################################################| 100/100 [00:01<00:00, 85.55it/s]


 [ xxx ] Parsing sniffed Connections.....


 TCP >> Thursday, December  12, 2019 07:17:59 192.168.43.10:49238        == to ==> 35.186.224.53:443
 TCP >> Thursday, December  12, 2019 07:17:59 192.168.43.10:49238        == to ==> 35.186.224.53:443
 TCP >> Thursday, December  12, 2019 07:17:59 35.186.224.53:443        == to ==> 192.168.43.10:49238
 TCP >> Thursday, December  12, 2019 07:17:59 35.186.224.53:443        == to ==> 192.168.43.10:49238
 TCP >> Thursday, December  12, 2019 07:17:59 35.186.224.53:443        == to ==> 192.168.43.10:49238
 TCP >> Thursday, December  12, 2019 07:17:59 35.186.224.53:443        == to ==> 192.168.43.10:49238
 TCP >> Thursday, December  12, 2019 07:17:59 35.186.224.53:443        == to ==> 192.168.43.10:49238
 TCP >> Thursday, December  12, 2019 07:17:59 192.168.43.10:49238        == to ==> 35.186.224.53:443
 TCP >> Thursday, December  12, 2019 07:17:59 192.168.43.10:49238        == to ==> 35.186.224.53:443
 TCP >> Thursday, December  12, 2019 07:17:59 192.168.43.10:49238        == to ==> 35.186.224.53:443

 .....
```


#### Parses for possible covert communication in ICMP data field

```
python3 netminey.py -cv icmp -in icmpcoverttest.pcap 
```

Tries to identify possible covert communication in ICMP data fields. 
It compares payload with standard ping payloads as hexstreams:

```
Windows - 6162636465666768696a6b6c6d6e6f7071727374757677616263646566676869
OSX - {there is a variable part here}08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637
```
When the payload and the standard ping hexstreams matches, it prints: [ xxx ] Standard ping!
if not, it prints the packet. 

Output: 

```
[ xxx ] Load PCAP.....
 [ >> ] testicmpcovert.pcap loaded


1337: 100%|###############################################################################################| 100/100 [00:01<00:00, 88.05it/s]


 [ xxx ] Parsing for possible ICMP covert communication.....


:::: Communication: 127.0.0.1 <--> 127.0.0.1 :::: 
    Type: 8 
    Code: 0 
    ID: 0 
    Payload (UTF-8): AAAAAAAAAAAAAAAAAAAAAAAAA

....

[ xxx ] Standard ping! 
```

#### Shows connection overview, parses for DNS, HTTP connections and extract payloads

```
python3 netminey.py --all -in dnstxt.pcap 
```


#### Searches for strings in RAW payload in PCAP

You can either specify a string to search for:

```
python3 netminey.py -f AAAA -in testicmpcovert.pcap
```

the default search looks for the strings: "user" and "pass"

```
python3 netminey.py -f -in testicmpcovert.pcap
```

```

 [ xxx ] Load PCAP.....
 [ >> ] testicmpcovert.pcap loaded


1337: 100%|#######################################################################################################################| 100/100 [00:01<00:00, 84.58it/s]


:::: Communication: 127.0.0.1 <--> 127.0.0.1 :::: 
    Payload (UTF-8): AAAAAAAAAAAAAAAAAAAAAAAAA

```

### Testing

In the folder test are test pcaps to play around, if you need more go to: [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/training-exercises.html)
there are some great exercices. 
There is also a test output folder from the parsing function from the 2019-08-20-traffic-analysis-exercise.pcap.


### Important note

Be careful if you want to analyse huge PCAP's, it's loaded into your memory. 
To reduce the size of the PCAP, try out [TRIM]( https://www.netresec.com/?page=Blog&month=2017-12&post=Don%27t-Delete-PCAP-Files---Trim-Them) from netrecsec.

## Authors

* **@joelgun**  - [Twitter](https://twitter.com/joelgun)

## License

This project is licensed under the GNU License - see the [LICENSE](LICENSE) file for details

## Acknowledgments

* secdev's Scapy library - [GitHub](https://github.com/secdev/scapy)

