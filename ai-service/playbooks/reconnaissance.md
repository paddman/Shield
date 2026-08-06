# Reconnaissance and Port Scan Response

## Trigger
A source touches many destination ports or hosts in a short period, Suricata raises scan alerts, or Zeek shows broad connection fan-out.

## Validate
1. Confirm unique destination ports, unique hosts, duration, protocol, and packet volume.
2. Identify whether the source belongs to an approved vulnerability scanner, monitoring system, or administrator.
3. Enrich public source IPs with threat intelligence and ASN context.
4. Check whether probing was followed by authentication, exploitation, or payload delivery.

## Respond
- Capture a short PCAP for evidence.
- Rate-limit or block an unapproved external source after approval.
- For internal sources, inspect the endpoint process and owner before containment.
- Escalate when reconnaissance is followed by successful access.
