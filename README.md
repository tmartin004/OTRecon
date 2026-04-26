# PCAP OT Host Parser

## Overview

`OTRecon` is a passive PCAP parser for host discovery and common OT/ICS
traffic identification. It reads an existing `.pcap` or `.pcapng` file and reports
observed hosts, MAC addresses, conversations, ports, likely vendors, OT protocols,
and basic asset role hints.

It does **not** scan, probe, exploit, or transmit traffic.

## Features

- Passive host discovery from packet captures
- IP and MAC address collection
- Top conversation summary
- Common OT/ICS protocol detection
- Basic OT role hints, such as:
  - possible PLC
  - possible HMI
  - possible engineering workstation
  - possible BACnet building automation device
- Lightweight vendor hints from known MAC OUIs
- JSON export
- CSV export
- Safe synthetic demo PCAP generator

## OT / ICS Detection Coverage

The parser looks for common OT protocols using ports, EtherTypes, and limited
payload heuristics.

Current detections include:

- Modbus/TCP — TCP/502
- Siemens S7comm / ISO-TSAP — TCP/102
- DNP3 — TCP/UDP 20000
- EtherNet/IP CIP — TCP/UDP 44818, UDP/2222
- BACnet/IP — UDP/47808
- IEC 60870-5-104 — TCP/2404
- OPC UA — TCP/4840
- MQTT — TCP/1883, TCP/8883
- CoAP — UDP/5683, UDP/5684
- SNMP — UDP/161, UDP/162
- Profinet — EtherType 0x8892 and selected Profinet-related ports
- LLDP — EtherType 0x88cc

## Requirements

- Python 3.9+
- Scapy

Install dependencies:

```bash
pip install scapy
```

## Basic Usage

```bash
python3 otrecon.py capture.pcap
```

Enable reverse DNS lookups:

```bash
python3 otrecon.pyy capture.pcap --dns
```

Limit printed OT findings and conversations:

```bash
python3 otrecon.py capture.pcap --top 50
```

## Export Options

Export full results to JSON:

```bash
python3 otrecon.py capture.pcap --json results.json
```

Export CSV files:

```bash
python3 otrecon.py capture.pcap --csv-prefix results
```

This creates:

```text
results_hosts.csv
results_conversations.csv
results_ot_findings.csv
```

Use both JSON and CSV:

```bash
python3 otrecon.py capture.pcap --json results.json --csv-prefix results
```

## Demo PCAP

A synthetic demo PCAP is included:

```text
sample_ot_demo.pcap
```

You can run:

```bash
python3 otrecon.py sample_ot_demo.pcap --json demo_results.json --csv-prefix demo_results
```

You can also regenerate the sample PCAP:

```bash
python3 generate_sample_pcap.py
```

The demo includes artificial examples of:

- ARP
- Modbus/TCP
- S7comm / ISO-TSAP
- EtherNet/IP
- BACnet/IP
- OPC UA
- Normal HTTPS traffic for contrast

## Example Output

```text
192.168.10.10
  MACs:       00:1b:1b:10:20:30
  Vendors:    Siemens
  Sent:       0
  Received:   3
  Ports:      502, 102
  Protocols:  TCP(2)
  OT Traffic: Modbus/TCP(1), Siemens S7comm / ISO-TSAP(1)
  Role Hints: Possible PLC / Modbus server, Possible Siemens PLC
```

## Notes and Limitations

This tool is intended for quick visibility and triage. OT fingerprinting is
best-effort and should not be treated as authoritative attribution.

Protocol detection is based mostly on:

- well-known ports
- selected EtherTypes
- simple payload signatures
- MAC OUI hints

Encrypted traffic, non-standard ports, tunneled traffic, and incomplete captures
may reduce accuracy.

## Safe Use

This is a passive analysis tool. It is suitable for reviewing existing packet
captures from internal, authorized assessments and lab environments.
