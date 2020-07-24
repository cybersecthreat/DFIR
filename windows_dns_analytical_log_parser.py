# -*- coding: UTF-8 -*-

import re
from collections import OrderedDict
import csv
import binascii
from dnslib import *
import sys, getopt
import platform
MajorPythonVersion=(platform.python_version().split('.')[0])
if MajorPythonVersion=='2':
 reload(sys)
 sys.setdefaultencoding('utf8')

def main(argv):

    ## Use the follow step to export expected format
    ## Disable Microsoft-Windows-DNSServer/Analytical Log
    #wevtutil sl "Microsoft-Windows-DNSServer/Analytical" /e:false
    #move C:\Windows\System32\winevt\Logs\Microsoft-Windows-DNSServer%4Analytical.etl C:\temp\
    ## Enable Microsoft-Windows-DNSServer/Analytical Log
    #Set-DnsServerDiagnostics -All $true
    ## Either use one of the following command to export the DNSServer/Analytical Event Log to expected text file format.
    ## This one will filter all Event ID except Event ID 256 or 257
    #wevtutil qe /lf "C:\temp\Microsoft-Windows-DNSServer%4Analytical.etl" /q:"*[System[(EventID=256 or EventID=257)]]" /f:text > C:\temp\Microsoft-Windows-DNSServer_Analytical.txt
    #wevtutil qe /lf "C:\temp\Microsoft-Windows-DNSServer%4Analytical.etl" /f:text > C:\temp\Microsoft-Windows-DNSServer_Analytical_full.txt
    
    if (len(sys.argv) != 2):
         print 'python3 windows_dns_analytical_log_parser.py -i <inputfile> -o <outputfile>'
         sys.exit()        

    inputfile = ''
    outputfile = ''
    try:
      opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
    except getopt.GetoptError:
      print 'python3 windows_dns_analytical_log_parser.py -i <inputfile> -o <outputfile>'
      sys.exit(2)
    for opt, arg in opts:
      if opt == '-h':
         print 'python3 windows_dns_analytical_log_parser.py -i <inputfile> -o <outputfile>'
         sys.exit()
      if opt in ("-i", "--ifile"):
         inputfile = arg
      else:
         print 'python3 windows_dns_analytical_log_parser.py -i <inputfile> -o <outputfile>'
         sys.exit()          
      if opt in ("-o", "--ofile"):
         outputfile = arg
      else:
         print 'python3 windows_dns_analytical_log_parser.py -i <inputfile> -o <outputfile>'
         sys.exit()
    print 'Now processing Windows DNS analytical"', inputfile

    # Open file as file object and read to string
    ifile = open(inputfile,'r')

    # Read file object to string
    text = ifile.read()

    # Close file object
    ifile.close()

    # Regex pattern
    pattern_meas = re.compile(r"""Event\[\d+\]:\n\s+Log\sName:\s(?P<DNS_LogName>.*?)\n\s+Source:\s(?P<DNS_Source>.*?)\n\s+Date:\s(?P<DNS_DateTime>.*?)\n\s+Event\sID:\s(?P<DNS_EventID>.*?)\n\s+Task:\s(?P<DNS_Task>.*?)\n\s+Level:\s(?P<DNS_Level>.*?)\n\s+Opcode:\s(?P<DNS_Opcode>.*?)\n\s+Keyword:\s(?P<DNS_Keyword>.*?)\n\s+User:\s(?P<DNS_User>.*?)\n\s+User\sName:\s(?P<DNS_UserName>.*?)\n\s+Computer:\s(?P<DNS_Computer>.*?)\n\s+Description:\s\n(?P<DNS_DATA_TYPE>.*?):\s(?P<DNS_Description>.*?);\sPacketData=0x(?P<DNS_PacketData>.*)""", re.VERBOSE | re.MULTILINE)

    csv_columns = ["DNS_LogName","DNS_Source","DNS_DateTime","DNS_EventID","DNS_Task","DNS_Level","DNS_Opcode","DNS_Keyword","DNS_User","DNS_UserName","DNS_Computer","DNS_DATA_TYPE","DNS_Description","DNS_PacketData","RDATA_decoded","TCP","Source","Destination","InterfaceIP","RD","QNAME","QNAME_IDN","QTYPE","XID","Port","Flags","ServerScope","CacheScope","AA","AD","DNSSEC","RCODE","Scope","Zone","SECURE","ZoneScope","Reason"]

    with open(outputfile, 'ab') as output_file:
        dict_writer = csv.DictWriter(output_file, csv_columns)
        dict_writer.writeheader()

        for match in pattern_meas.finditer(text):
            #output = "%s,%s" % (match.group('DNS_LogName'), match.group('DNS_Source'))
            #file_times.write(output)

            DNSOrderedDict = OrderedDict()
            
            DNSOrderedDict["DNS_LogName"]=match.group('DNS_LogName')
            DNSOrderedDict['DNS_Source']=match.group('DNS_Source')
            DNSOrderedDict['DNS_DateTime']=match.group('DNS_DateTime')
            DNSOrderedDict['DNS_EventID']=match.group('DNS_EventID')
            DNSOrderedDict['DNS_Task']=match.group('DNS_Task')
            DNSOrderedDict['DNS_Level']=match.group('DNS_Level')
            DNSOrderedDict['DNS_Opcode']=match.group('DNS_Opcode')
            DNSOrderedDict['DNS_Keyword']=match.group('DNS_Keyword')
            DNSOrderedDict['DNS_User']=match.group('DNS_User')
            DNSOrderedDict['DNS_UserName']=match.group('DNS_UserName')
            DNSOrderedDict['DNS_Computer']=match.group('DNS_Computer')
            DNSOrderedDict['DNS_DATA_TYPE']=match.group('DNS_DATA_TYPE')
            DNSOrderedDict['DNS_Description']=match.group('DNS_Description')
            DNSOrderedDict['DNS_PacketData']=match.group('DNS_PacketData')

            try:
                packet = binascii.unhexlify(match.group('DNS_PacketData'))
                RDATA_decoded = DNSRecord.parse(packet)
                DNSOrderedDict['RDATA_decoded']=RDATA_decoded
            except:
                print("Error in decoded DNS Packet")

            DNSOrderedDict['TCP']=""
            DNSOrderedDict['Source']=""
            DNSOrderedDict['Destination']=""
            DNSOrderedDict['InterfaceIP']=""
            DNSOrderedDict['RD']=""
            DNSOrderedDict['QNAME']=""
            DNSOrderedDict['QNAME_IDN']=""
            DNSOrderedDict['QTYPE']=""
            DNSOrderedDict['XID']=""
            DNSOrderedDict['Port']=""
            DNSOrderedDict['Flags']=""
            DNSOrderedDict['ServerScope']=""
            DNSOrderedDict['CacheScope']=""
            DNSOrderedDict['AA']=""
            DNSOrderedDict['AD']=""
            DNSOrderedDict['DNSSEC']=""
            DNSOrderedDict['RCODE']=""
            DNSOrderedDict['Scope']=""
            DNSOrderedDict['Zone']=""
            DNSOrderedDict['SECURE']=""
            DNSOrderedDict['ZoneScope']=""    

            DNS_DescriptionOrderedDict = OrderedDict(map(lambda x: x.split('='), match.group('DNS_Description').split('; ')))
            try:
                if DNS_DescriptionOrderedDict['QNAME']!="":
                    DNSOrderedDict['QNAME_IDN']=DNS_DescriptionOrderedDict['QNAME'].decode("idna")
            except:
                print("Error in decode QName:" + DNS_DescriptionOrderedDict['QNAME']) 

            DNSOrderedDict.update(DNS_DescriptionOrderedDict)
            
            try:
                dict_writer.writerow(DNSOrderedDict)
            except:
                print("Error in writing csv:" + DNS_DescriptionOrderedDict['QNAME'])

    output_file.close()
    print 'Output file is "', outputfile

if __name__ == "__main__":
   main(sys.argv[1:])
