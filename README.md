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

Requirements:
DNSplice uses the requests module for python. This will need to be installed to run.
command: pip install requests

To run:
At command prompt: python dnsplice_v1.py -i <inputfile> -v <virustotal apikey> -t <threatgrid apikey>

Options:
-i, --input : DNS log filename (REQUIRED)
-v, --vtkey : VirusTotal API key (OPTIONAL)
-t, --tgkey : Cisco ThreatGrid API key (OPTIONAL)

Output:
DNS logs are parsed to include timedatestamp, client IP, uri requested, and domain, and are outputted automagically to output.csv
in the directory DNSplice is run from.
VirusTotal Domain Report lookups are performed every 20 seconds (3/min) and are outputted to vt_output.csv. For large files, this
make take some time. 
ThreatGrid Lookups are limited to 50 lookups per day. Top ten most and least requested domains are requested from ThreatGrid, and
are outputted to tg_output.csv. Requests are made every 20 seconds. 


