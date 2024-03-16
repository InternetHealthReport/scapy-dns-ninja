#!/usr/bin/env python
### adapted from : http://thepacketgeek.com/scapy-p-09-scapy-and-dns/
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSRR
from scapy.sendrecv import sniff, send
import sys
from random import shuffle
import re
from yaml import load, Loader
import traceback
import os.path
from multiprocessing import Pool

def read_conffile( filename ):
   conf = {}
   try:
      with open(filename,'rb') as fh:
         conf = load(fh, Loader)
   except:
      sys.stderr.write("Error reading config file: %s\n" % ( filename ))
   return conf

conf = read_conffile('ninja-server.conf')
lists = {'v4':{},'v6':{}, 'cnames':{}}
lists_read=0

def read_destfile( list_name, lists, proto ):
    filename = "./%s/dests.%s.txt" % ( list_name, proto )
    sys.stderr.write( "trying to read list %s / proto %s from file: %s\n" % ( list_name, proto, filename ) )
    dests = []
    with open(filename,'r') as fh:
        for line in fh:
            line = line.rstrip('\n')
            dests.append( line ) 
    shuffle( dests )
    if not proto in lists:
        lists[ proto ] = {}
    lists[ proto][ list_name ] = { 
        'dests': dests,
        'mtime': os.path.getmtime( filename ),
        'length': len(dests),
        'dest_idx': 0
    }
    sys.stderr.write( "list %s / proto %s successfully loaded\n" % ( list_name, proto ))
    return lists

def generate_response( pkt, dest, proto ):
   ptype='A'
   if proto=='v6':
      ptype='AAAA'
   elif proto=='cnames':
      ptype='CNAME'
   resp = IP(dst=pkt[IP].src, id=pkt[IP].id)\
      /UDP(dport=pkt[UDP].sport, sport=53)\
      /DNS( id=pkt[DNS].id,
            aa=1, #we are authoritative
            qr=1, #it's a response
            rd=pkt[DNS].rd, # copy recursion-desired
            qdcount=pkt[DNS].qdcount, # copy question-count
            qd=pkt[DNS].qd, # copy question itself
            ancount=1, #we provide a single answer
            an=DNSRR(rrname=pkt[DNS].qd.qname, type=ptype, ttl=1, rdata=dest ),
      )
   return resp

def record( src, list_name, proto, dest_ip ):
   ''' write we sent this pkt somewhere '''
   return "src=%s list=%s proto=%s dest=%s" % ( src, list_name, proto, dest_ip )

def have_listfile( list_name, proto ):
   filename="./%s/dests.%s.txt" % ( list_name, proto )
   if os.path.exists( filename ):
      return True
   else:
      return False

def getResponse(pkt, conf, re_getlist):
    global dest_idx
    global lists
    if(DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0  
            and pkt[IP].dst == conf['ServerIP']):
        try:
            qname = pkt[DNS].qd.qname.decode().lower()
            pkt_proto = None
            if pkt[DNS].qd.qtype == 1:
                pkt_proto='v4'  
            elif pkt[DNS].qd.qtype == 28:
                pkt_proto='v6'  
            else: ### won't respond to non A or AAAA packet
                return

            list_match = re.search( re_getlist, qname )
            if list_match and os.path.exists( "./%s" % ( list_match.group(1) ) ):
                #this checks if the path exists
                list_name = list_match.group(1)
                if(have_listfile( list_name, pkt_proto ) and ( list_name not in lists[pkt_proto] 
                            or os.path.getmtime("./%s/dests.%s.txt" % (list_name, pkt_proto) ) > lists[pkt_proto][list_name]['mtime']) ):
                    ## read if the list wasn't read yet or if the mtime changed
                    try:
                        read_destfile( list_name, lists, pkt_proto )
                    except: 
                        # list dir does exist, but not for the right proto. return nothing
                        sys.stderr.write("%s dir exists, but no dests.%s.txt file\n" % ( list_name, pkt_proto ))
                        return
                ##if not dests.v[46].txt , see if there is a dests.cnames.txt file
                elif have_listfile( list_name, 'cnames') and ( list_name not in lists['cnames'] or os.path.getmtime("./%s/dests.cnames.txt" % (list_name) ) > lists['cnames'][list_name]['mtime']):
                    try:
                        read_destfile( list_name, lists, 'cnames' )
                    except: 
                        # list dir does exist, but not for the right proto. return nothing
                        sys.stderr.write("%s dir exists, but no dests.%s.txt file\n" % ( list_name, 'cnames' ))
                        return

                ## set pkt_proto to 'cnames' if v4 and v6 list don't exist
                if list_name in lists['cnames'] and not list_name in lists['v4'] and not list_name in lists['v6']:
                    pkt_proto = 'cnames'
                try:
                    dest_idx = lists[pkt_proto][list_name]['dest_idx']
                    dest_ip = lists[pkt_proto][list_name]['dests'][dest_idx]
                    if lists[pkt_proto][list_name]['dest_idx'] < lists[pkt_proto][list_name]['length']-1:
                        lists[pkt_proto][list_name]['dest_idx'] += 1
                    else:
                        sys.stderr.write("list reset %s/%s\n" % ( pkt_proto,list_name ))
                        shuffle( lists[pkt_proto][list_name]['dests'] )
                        lists[pkt_proto][list_name]['dest_idx'] = 0 ## reset to beginning
                    resp = generate_response( pkt, dest_ip, pkt_proto )
                    send(resp,verbose=0)
                    return record( pkt[IP].src, list_name, pkt_proto, dest_ip )
                except:
                    sys.stderr.write("error on packet: %s\n" % ( pkt.summary() ))
                    sys.stderr.write(str(sys.exc_info()))
        except:
            sys.stderr.write("%s" % ( traceback.print_tb( sys.exc_info()[2] ) ))

with Pool(processes=8) as pool:
    sys.stderr.write( "config loaded, starting operation\n" )
    # there is no TCP because we don't listen on port 53
    filter = "udp port 53 and ip dst %s" % (conf['ServerIP'])
#    #TODO better regex
    re_getlist = re.compile(r'([a-z0-9\-]+)\.%s\.$' % ( conf['ServerDomain'] ) )
    scap = sniff(filter=filter,store=0,prn=lambda x: pool.apply_async(getResponse, (x, conf, re_getlist)))
    scap.summary()
