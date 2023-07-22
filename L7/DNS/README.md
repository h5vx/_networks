# L7/DNS

## dnsq.py
- Implementation of DNS protocol in python
- It is not full and not accurate implementation of [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035) (1987) specification

### Requirements
- Python >= 3.10

### Example usage
```bash
# Resolve IP of example.com
python dnsq.py example.com A

# Inverse query of gmail.com using name server 8.8.8.8
python dnsq.py -i 64.233.161.83 PTR --ns 8.8.8.8
```