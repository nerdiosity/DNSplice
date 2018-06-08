#######################################################################################
# DNSplice was created by Shelly Giesbrecht (nerdiosity) to assist incident responders
# to quickly and easily parse client query events from ugly DNS logs for 
# Microsoft Windows 2003/2008R2 (DNS debug log) to Windows 2012R2/2016 (DNS Analytical
# log) into a format (CSV) suitable for additional analysis or insertion into a larger
# timeline.
# version: DNSplice v1.0
# date of release: June 8, 2018
#
# This project was created in answer to a problem encountered by me over years of doing
# IR, and as a way of learning to code. Comments or suggestions are greatly appreciated.
# email: info@nerdiosity.com twitter: @nerdiosity 
# github: https://github.com/nerdiosity/DNSplice
########################################################################################

#!/usr/bin/env python
import re
import sys
import datetime
import argparse
import csv
from collections import Counter
import requests # this is required and will need to be installed if not already done. "pip install request[security]"
import time

# Getting some arguments
parser = argparse.ArgumentParser(description='Add a filename')
parser.add_argument('-i', '--input', help='Input a filename', required=True) # Get a dns log as input
parser.add_argument('-v', '--vtkey', help='Input your VT API key', required=False) # Optional: Enter a VirusTotal API key 
parser.add_argument('-t', '--tgkey', help='Input your  TG API key', required=False) # Optional: Enter a Cisco ThreatGrid API key 
args = parser.parse_args()

# Set up variables required
inputfile = ''
outputfile = ''
splice_date = ''
splice_sndrcv = ''
splice_client = ''
splice_rtype = ''
splice_datetime = ''   
splice_uriquery = ''
splice_domain = ''
split_domain = ''
join_domain = ''
csv_output = ''
tg_key = ''

# Set up lists
domain_list = []
client_list = []
top_domains = []
least_domains = []
temp_top = []
temp_least = []
ten_top = []
ten_least = []


print "#############################################################"
print "#  DNSplice v1 by nerdiosity"
print "#  Parse your ugly DNS logs!"
print "#############################################################"
print "#"
print "#"

#######################################################################################
# Parsing all the file!
#######################################################################################
# Create a csv to output the parsed date to and give it some headers
outputfile = open('output.csv', 'w')
with outputfile:
    output_fields = ['DateTime', 'ClientIP', 'URIQuery', 'Domain']
    writer = csv.DictWriter(outputfile, fieldnames=output_fields)
    writer.writeheader()
    # writer.writerow({'DateTime' : splice_datetime, 'ClientIP' : splice_client, 'URIQuery' : splice_domain, 'Domain' : join_domain})
outputfile.close()
 
# Open the dns log file given as input   
with open(args.input,'r') as dns_file:
    for line in dns_file:
        if re.search( r'(.*) PACKET (.*?) .*', line, re.M|re.I): # Look for lines in Windows 2003-2008R2 DNS debug files with "PACKET" in them
            if re.match('^\d\d\d\d\d\d\d\d', line):         # For Windows 2003 type files, look for lines that start with date style YYYYMMDD
                jack = line.split()                         # Split the line into fields
                splice_date = jack[0] + ' ' + jack[1]       # Splice together the date and time indexes into datetime
                #splice_sndrcv = str(jack[6]).strip('[]')   # Create a variable to hold the value of the direction of traffic
                splice_client = str(jack[7]).strip('[]')    # Create a variable to hold the value of the client IP
                splice_rtype = str(jack[-2]).strip('[]')    # Create a variable to hold the value of the record type
                splice_datetime = datetime.datetime.strptime(splice_date, '%Y%m%d %H:%M:%S')     # Create a variable to hold the value of a formatted split_date
                splice_uriquery = re.sub(r"\(\d+\)",r".", str(jack[-1]).strip('[]'))
                splice_domain = splice_uriquery[1:-1]               # create variable to hold the value of splice_uriquery with the leading and trailing '.' stripped off
                split_domain = splice_domain.split('.')              # create a variable to hold the value of splitting split_domain by the '.'
                join_domain = str(split_domain[-2:-1]).strip("'[]'") + '.' + split_domain[-1] # create a variable to hold the value of joining the last two elements of split_domain
                if jack[9] != 'R':                                                              # this removes any response as we are looking for only queries made
                    if re.match('^(10\.\d{1,3}|192\.168|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|127\.0\.0\.1)', splice_client): # This limits the client IPs to only RFC1918 addresses
                        # This next piece opens the output file we created, and appends each line to it with value for fields: 'DateTime', 'ClientIP', 'URIQuery', and 'Domain'
                        outputfile = open('output.csv', 'a') 
                        with outputfile:
                            output_fields = ['DateTime', 'ClientIP', 'URIQuery', 'Domain']
                            writer = csv.DictWriter(outputfile, fieldnames=output_fields)
                            #writer.writeheader()
                            writer.writerow({'DateTime' : splice_datetime, 'ClientIP' : splice_client, 'URIQuery' : splice_domain, 'Domain' : join_domain})
                        client_list.append(splice_client)               # add all the client IPs to a list
                        domain_list.append(join_domain)                 # add all the domain names to a list                              
            elif re.match('^\d{1,2}\/\d{1,2}\/\d{4}',line):     # For Windows 2008R2 type files, look for lines that start with date style MM/DD/YYYY
                jack = line.split()
                splice_date = jack[0] + ' ' + jack[1] + ' ' + jack[2]
                splice_datetime = datetime.datetime.strptime(splice_date, '%m/%d/%Y %I:%M:%S %p')
                splice_sndrcv = str(jack[7]).strip('[]')
                splice_client = str(jack[8]).strip('[]')
                splice_rtype = str(jack[-2]).strip('[]')
                splice_uriquery = re.sub(r"\(\d+\)",r".", str(jack[-1]).strip('[]'))
                splice_domain = splice_uriquery[1:-1]               
                split_domain = splice_domain.split('.')              
                join_domain = str(split_domain[-2:-1]).strip("'[]'") + '.' + split_domain[-1]                
                
                if jack[10] != 'R':
                    if re.match('^(10\.\d{1,3}|192\.168|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|127\.0\.0\.1)', splice_client):
                        outputfile = open('output.csv', 'a')
                        with outputfile:
                            output_fields = ['DateTime', 'ClientIP', 'URIQuery', 'Domain']
                            writer = csv.DictWriter(outputfile, fieldnames=output_fields)
                            #writer.writeheader()
                            writer.writerow({'DateTime' : splice_datetime, 'ClientIP' : splice_client, 'URIQuery' : splice_domain, 'Domain' : join_domain})
                        client_list.append(splice_client)
                        domain_list.append(join_domain)
                        
        elif re.match('^Microsoft-Windows-DNS-Server',line): # For Windows 2012R2-2016 type files, look for lines that start with Microsoft-Windows-DNS-Server
            #from datetime import datetime
            jack = line.split()
            splice_eventID = str(jack[3]).strip(",")        # create a variable to hold the value the event ID
            splice_date = long(str(jack[17]).strip(","))    # create a variable to hold the value the date, convert to string to remove a comma, then convert to long
            splice_datetime = datetime.datetime.fromtimestamp((splice_date - 116444736000000000) // 10000000) # create a variable to hold the formatted date 
            #print splice_datetime
            splice_client = str(re.sub(r'"', r'',jack[22])).strip(',')
            #print splice_client
            splice_uriquery = str(re.sub(r'\.\"\,', r'', jack[24])).strip('"')
            split_domain = splice_uriquery.split('.')              # create a variable to hold the value of splitting splice_uriquery by the '.'
            splice_domain = str(split_domain[-2:-1]).strip("'[]'") + '.' + split_domain[-1] # create a variable to hold the value of joining the last two elements of split_domain                         
            if re.match(r"256",splice_eventID):                     # DNS Analytical log event 256 is for queries and that's all we want
                #print splice_datetime, splice_client, splice_uriquery, splice_domain
                if re.match('^(10\.\d{1,3}|192\.168|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|127\.0\.0\.1)', splice_client): 
                    outputfile = open('output.csv', 'a')
                    with outputfile:
                        output_fields = ['DateTime', 'ClientIP', 'URIQuery', 'Domain']
                        writer = csv.DictWriter(outputfile, fieldnames=output_fields)
                        #writer.writeheader()
                        writer.writerow({'DateTime' : splice_datetime, 'ClientIP' : splice_client, 'URIQuery' : splice_uriquery, 'Domain' : splice_domain})
                    client_list.append(splice_client)
                    domain_list.append(splice_domain)
        elif re.match('^Information',line):
                        #jack = line.split(',')
                        jack = re.split(';|,',line)
                        #print jack
                        splice_eventID = str(jack[3])
                        #print splice_eventID
                        splice_date = jack[1]
                        splice_datetime = datetime.datetime.strptime(splice_date, '%m/%d/%Y %I:%M:%S %p')
                        #splice_datetime = datetime.datetime.frmotimestamp((splice_date - 116444736000000000) // 10000000)
                        #print splice_datetime
                        splice_client = re.sub(r'Source=|Destination=', r'',jack[7])
                        #print splice_client
                        splice_uriquery = re.sub(r'Zone=|QNAME=', r'',jack[9].strip("."))
                        #print splice_uriquery
                        split_domain = splice_uriquery.split('.')              # create a variable to hold the value of splitting split_domain by the '.'
                        splice_domain = str(split_domain[-2:-1]).strip("'[]'") + '.' + split_domain[-1] # create a variable to hold the value of joining the last two elements of split_domain 
                        #print splice_domain
                        if re.match(r"256",splice_eventID):
                            #print splice_datetime,",",splice_client,",",splice_uriquery,",",splice_domain
                            #s = ","
                            #seq = {str(splice_datetime), splice_client, splice_uriquery, splice_domain}
                            #print s.join(seq),"\n"
                                #print splice_datetime, splice_client, splice_uriquery, splice_domain
                            outputfile = open('output.csv', 'a')
                            with outputfile:
                                output_fields = ['DateTime', 'ClientIP', 'URIQuery', 'Domain']
                                writer = csv.DictWriter(outputfile, fieldnames=output_fields)
                                #writer.writeheader()
                                writer.writerow({'DateTime' : splice_datetime, 'ClientIP' : splice_client, 'URIQuery' : splice_uriquery, 'Domain' : splice_domain})
                            client_list.append(splice_client)
                            domain_list.append(splice_domain)                        
# Parsing of files is COMPLETE!


#######################################################################################
# Create some stats!
# Which are: 
# Client with most domain requests
# Top ten requested domains
# Top ten least requested domains
#######################################################################################
# Create a count of all the IPs in client_list
cnt = Counter(client_list)
# Determine the top ten client IPS with the most domain requests and print it to the console
top_clients = cnt.most_common(10) 
print "#############################################################"
print 'DNSplice Statistics'
print "#############################################################"
print '# The top 10 requesting client IPs are:'
print str(top_clients).strip("['']")
print "-------------------------------------------------------------"

# Create a count of all the domains in domain_list
cnt = Counter(domain_list)

# Determine the top ten most requested domains, put them into a list called top_domains, and print it to the console
top_domains.append(cnt.most_common(10))
print '#  top 10 requested domains are:'
print str(top_domains).strip("['']")
print "-------------------------------------------------------------"

# This is a really ridiculous way I stripped the count from the key pair of domain/count in top_domain, and put the top ten domains into a list called ten_top
temp_top = str(top_domains)
#print temp_top
temp_top2 = temp_top.strip("['']")
#print temp_top2
temp_top3 = re.sub("\(\'", r"",temp_top2)
#print temp_top3
temp_top4 = re.sub("\'\,\s\d+\)", r"",temp_top3)
#print temp_top4
temp_top5 = re.sub(r" ",r"",temp_top4)
ten_top = temp_top5.split(',')
#print(ten_top)



# Determine the top ten least requested domains, put them into a list called least_domains, and print it to the console
least_domains.append(cnt.most_common()[:-11:-1])
print '# The top 10 least domains are:'
print str(least_domains).strip("['']")
print "#############################################################"
print "#"
print "#" 

# This is a really ridiculous way I stripped the count from the key pair of domain/count in least_domain, and put the least ten domains into a list called ten_least
temp_least = str(least_domains)
#print temp_least
temp_least2 = temp_least.strip("['']")
#print temp_least2
temp_least3 = re.sub("\(\'", r"",temp_least2)
#print temp_least3
temp_least4 = re.sub("\'\,\s\d+\)", r"",temp_least3)
#print temp_least4
temp_least5 = re.sub(r" ",r"",temp_least4)
ten_least = temp_least5.split(',')
#print(ten_least)


# and then I joined the lists
tg_domains = ten_top + ten_least
#print(tg_domains)



#######################################################################################
# VirusTotal Domain Report Lookup
# You will need at least a VT Public API key to do this
# This step is optional
# VT Public API lookups are limited to 4/minutes. This runs every 20sec (3/min) as that
# seemed to work better
# Dumps the domain name and a nasty blob of json into a csv for any additional research
#######################################################################################
if args.vtkey is not None: # if you specified a VT API Key, all this neat stuff will happen:
    domain_set = set(domain_list)
    unique_domains = list(domain_set)
    
    vt_url = 'https://www.virustotal.com/vtapi/v2/url/report?apikey='
    print "#############################################################"
    print '# DNSplice - VirusTotal Domain Report'
    print "#############################################################"
    print '# Output is printed to vt_outout.csv. One lookup is performed every 20 sec'
    print "#############################################################"
    print "#"
    print "#"
    
    outputfile = open('vt_output.csv', 'w')
    with outputfile:
        output_fields = ['Domain', 'Domain Report']
        writer = csv.DictWriter(outputfile, fieldnames=output_fields)
        writer.writeheader()
        #writer.writerow({'Domain' : item, 'Domain Report' : response.json})
    outputfile.close()
    
    
    outputfile = open('vt_output.csv', 'a') # the domain and json block is appended to the vt_output csv
    with outputfile:
        for item in unique_domains:
            url = 'https://www.virustotal.com/vtapi/v2/domain/report'
            params = {'apikey': args.vtkey,'domain': item}
            response = requests.get(url, params=params)
            json_out = response.json()
            output_fields = ['Domain', 'Domain Report']
            writer = csv.DictWriter(outputfile, fieldnames=output_fields)
            #writer.writeheader()
            writer.writerow({'Domain' : item, 'Domain Report' : json_out})
            print item + " complete"
            print "-------------------------------------------------------------"
            time.sleep(20)
            
else:   # if you didn't specify a VT API Key, you will see this in the console
    print "#############################################################"
    print 'DNSplice - VirusTotal Domain Report'
    print "#############################################################"
    print "No api key was given. VT domain reports will not be run"
    print "#############################################################"
    print "#"
    print "#"     


#######################################################################################
# CISCO THREATGRID Domain Lookup
# You will need at least a TG API key to do this
# This step is optional
# TG lookups are limited to 50 per day so I've taken the top ten most and least requested
# domains for this search
# Dumps the domain name and a nasty blob of json into a csv for any additional research
#######################################################################################
if args.tgkey is not None: # if you specified a TG API Key, all this neat stuff will happen:
    #domain_set = set(domain_list)
    #unique_domains = list(domain_set)
    
    tg_url = 'https://panacea.threatgrid.com/api/v2/search/submissions?api_key='
    tg_key = args.tgkey
    print "#############################################################"
    print '# DNSplice - Cisco ThreatGrid Domain Report'
    print "#############################################################"
    print '# Output is printed to tg_outout.csv. One lookup is performed every 20 sec'
    print "#############################################################"
    print "#"
    print "#" 
    
    outputfile = open('tg_output.csv', 'w')
    with outputfile:
        output_fields = ['Domain', 'Domain Report']
        writer = csv.DictWriter(outputfile, fieldnames=output_fields)
        writer.writeheader()
        #writer.writerow({'Domain' : item, 'Domain Report : response.json})
    outputfile.close()
    
    
    outputfile = open('tg_output.csv', 'a') # the domain and json block is appended to the tg_output csv
    with outputfile:
        #print tg_domains
        for item in tg_domains:
            #print tg_url + tg_key + '&q=' + item
            url = tg_url + tg_key + '&q=' + item
            #print url
            response = requests.get(url)
            json_out = response.json()
            output_fields = ['Domain', 'Domain Report']
            writer = csv.DictWriter(outputfile, fieldnames=output_fields)
            #writer.writeheader()
            writer.writerow({'Domain' : item, 'Domain Report' : json_out})
            print item + " complete"
            print "-------------------------------------------------------------"
            time.sleep(15)
            
else:       # if you didn't specify a TG API Key, you will see this in the console
    print "#############################################################"
    print '# DNSplice - Cisco ThreatGrid Domain Report'
    print "#############################################################"
    print "# No api key was given. TG domain reports will not be run"
    print "#############################################################"



#######################################################################################
# This is the end of this run, but DNSplice is going to get better so come back, y'all!
#######################################################################################