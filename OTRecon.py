#!/usr/bin/env python3
"""
pcap_ot_hosts.py

Passive PCAP parser for host discovery and common OT/ICS traffic identification.

This tool does not scan, probe, or transmit packets. It only reads an existing
PCAP/PCAPNG file and summarizes observed hosts, conversations, and OT indicators.
"""

import argparse
import csv
import json
import socket
from collections import Counter, defaultdict
from pathlib import Path

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, Ether, ARP, Raw
except ImportError:
    print("Missing dependency: scapy")
    print("Install with: pip install scapy")
    raise SystemExit(1)


OT_PORTS = {
    502: "Modbus/TCP",
    102: "Siemens S7comm / ISO-TSAP",
    20000: "DNP3",
    44818: "EtherNet/IP CIP",
    2222: "EtherNet/IP I/O",
    47808: "BACnet/IP",
    2404: "IEC 60870-5-104",
    4840: "OPC UA",
    1883: "MQTT",
    8883: "MQTT over TLS",
    5683: "CoAP",
    5684: "CoAP over DTLS",
    161: "SNMP",
    162: "SNMP Trap",
    1962: "PCWorx / Phoenix Contact",
    34962: "Profinet DCP",
    34963: "Profinet RT",
    34964: "Profinet Context Manager",
}

OT_ETHERTYPES = {
    0x8892: "Profinet",
    0x88CC: "LLDP",
}

VENDOR_OUIS = {
    "00:0e:8c": "Siemens",
    "00:1b:1b": "Siemens",
    "00:05:ba": "Schneider Electric",
    "00:80:f4": "Rockwell Automation / Allen-Bradley",
    "00:00:bc": "Rockwell Automation / Allen-Bradley",
    "00:a0:45": "Phoenix Contact",
    "00:15:64": "Beckhoff Automation",
    "00:01:05": "Beckhoff Automation",
    "00:30:de": "WAGO",
    "00:60:77": "Omron",
    "00:00:54": "Schneider Electric",
    "00:1d:9c": "Moxa",
    "00:90:e8": "Moxa",
    "00:40:9d": "Digi International",
}

ROLE_HINTS = {
    "Modbus/TCP": {
        "server_port": 502,
        "server_role": "Possible PLC / Modbus server",
        "client_role": "Possible HMI / engineering workstation / historian",
    },
    "Siemens S7comm / ISO-TSAP": {
        "server_port": 102,
        "server_role": "Possible Siemens PLC",
        "client_role": "Possible Siemens engineering workstation or HMI",
    },
    "EtherNet/IP CIP": {
        "server_port": 44818,
        "server_role": "Possible Rockwell/Allen-Bradley PLC or adapter",
        "client_role": "Possible HMI / scanner / engineering workstation",
    },
    "BACnet/IP": {
        "server_port": 47808,
        "server_role": "Possible BACnet building automation device",
        "client_role": "Possible BAS workstation / controller",
    },
    "DNP3": {
        "server_port": 20000,
        "server_role": "Possible DNP3 outstation",
        "client_role": "Possible DNP3 master",
    },
    "IEC 60870-5-104": {
        "server_port": 2404,
        "server_role": "Possible IEC-104 controlled station",
        "client_role": "Possible IEC-104 control station",
    },
    "OPC UA": {
        "server_port": 4840,
        "server_role": "Possible OPC UA server",
        "client_role": "Possible OPC UA client",
    },
}


def resolve_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def mac_vendor(mac):
    if not mac:
        return None
    return VENDOR_OUIS.get(mac.lower()[0:8])


def get_ip_layer(pkt):
    if IP in pkt:
        return pkt[IP]
    if IPv6 in pkt:
        return pkt[IPv6]
    return None


def payload_bytes(pkt):
    if Raw in pkt:
        return bytes(pkt[Raw].load)
    return b""


def detect_by_payload(pkt):
    """Best-effort payload hints. These are intentionally conservative."""
    data = payload_bytes(pkt)
    hints = []

    if not data:
        return hints

    # Modbus/TCP MBAP header: transaction id, protocol id usually 0x0000,
    # length, unit id, then function code. This is only a heuristic.
    if TCP in pkt and (pkt[TCP].sport == 502 or pkt[TCP].dport == 502):
        if len(data) >= 8 and data[2:4] == b"\x00\x00":
            hints.append("Modbus/TCP")

    # OPC UA binary message types often begin with HEL, ACK, OPN, MSG, CLO.
    if TCP in pkt and (pkt[TCP].sport == 4840 or pkt[TCP].dport == 4840):
        if data[:3] in (b"HEL", b"ACK", b"OPN", b"MSG", b"CLO"):
            hints.append("OPC UA")

    # EtherNet/IP encapsulation commands: 0x0063 ListIdentity, 0x0065 RegisterSession,
    # 0x006f SendRRData, 0x0070 SendUnitData.
    if TCP in pkt and (pkt[TCP].sport == 44818 or pkt[TCP].dport == 44818):
        if len(data) >= 2 and data[:2] in (b"\x63\x00", b"\x65\x00", b"\x6f\x00", b"\x70\x00"):
            hints.append("EtherNet/IP CIP")

    return hints


def detect_ot_protocols(pkt):
    findings = []

    if Ether in pkt:
        eth_type = pkt[Ether].type
        if eth_type in OT_ETHERTYPES:
            findings.append(OT_ETHERTYPES[eth_type])

    if TCP in pkt:
        for port in (pkt[TCP].sport, pkt[TCP].dport):
            if port in OT_PORTS:
                findings.append(OT_PORTS[port])

    if UDP in pkt:
        for port in (pkt[UDP].sport, pkt[UDP].dport):
            if port in OT_PORTS:
                findings.append(OT_PORTS[port])

    findings.extend(detect_by_payload(pkt))
    return sorted(set(findings))


def update_role_hints(hosts, src_ip, dst_ip, sport, dport, protocols):
    for proto in protocols:
        role = ROLE_HINTS.get(proto)
        if not role:
            continue

        server_port = role["server_port"]

        if dport == server_port:
            hosts[dst_ip]["role_hints"].add(role["server_role"])
            hosts[src_ip]["role_hints"].add(role["client_role"])
        elif sport == server_port:
            hosts[src_ip]["role_hints"].add(role["server_role"])
            hosts[dst_ip]["role_hints"].add(role["client_role"])


def parse_pcap(filename, do_dns=False):
    packets = rdpcap(filename)

    hosts = defaultdict(lambda: {
        "macs": set(),
        "vendors": set(),
        "sent": 0,
        "received": 0,
        "ports": Counter(),
        "protocols": Counter(),
        "ot_protocols": Counter(),
        "role_hints": set(),
        "dns_name": None,
    })

    conversations = Counter()
    ot_findings = []

    for pkt in packets:
        src_mac = pkt[Ether].src if Ether in pkt else None
        dst_mac = pkt[Ether].dst if Ether in pkt else None

        if ARP in pkt:
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst

            hosts[src_ip]["sent"] += 1
            if src_mac:
                hosts[src_ip]["macs"].add(src_mac)
                vendor = mac_vendor(src_mac)
                if vendor:
                    hosts[src_ip]["vendors"].add(vendor)

            if dst_ip:
                hosts[dst_ip]["received"] += 1

            conversations[(src_ip, dst_ip, "ARP", "", "")] += 1
            continue

        ip = get_ip_layer(pkt)
        protocols = detect_ot_protocols(pkt)

        if not ip:
            if protocols:
                ot_findings.append({
                    "src": src_mac or "",
                    "dst": dst_mac or "",
                    "transport": "L2",
                    "sport": "",
                    "dport": "",
                    "protocols": protocols,
                    "summary": pkt.summary(),
                })
            continue

        src_ip = ip.src
        dst_ip = ip.dst

        hosts[src_ip]["sent"] += 1
        hosts[dst_ip]["received"] += 1

        if src_mac:
            hosts[src_ip]["macs"].add(src_mac)
            vendor = mac_vendor(src_mac)
            if vendor:
                hosts[src_ip]["vendors"].add(vendor)

        if dst_mac:
            hosts[dst_ip]["macs"].add(dst_mac)
            vendor = mac_vendor(dst_mac)
            if vendor:
                hosts[dst_ip]["vendors"].add(vendor)

        sport = ""
        dport = ""

        if TCP in pkt:
            transport = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            transport = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        else:
            transport = f"IP_PROTO_{getattr(ip, 'proto', 'unknown')}"

        if sport:
            hosts[src_ip]["ports"][sport] += 1
        if dport:
            hosts[dst_ip]["ports"][dport] += 1

        hosts[src_ip]["protocols"][transport] += 1
        hosts[dst_ip]["protocols"][transport] += 1

        conversations[(src_ip, dst_ip, transport, sport, dport)] += 1

        if protocols:
            update_role_hints(hosts, src_ip, dst_ip, sport, dport, protocols)

            for proto in protocols:
                hosts[src_ip]["ot_protocols"][proto] += 1
                hosts[dst_ip]["ot_protocols"][proto] += 1

            ot_findings.append({
                "src": src_ip,
                "dst": dst_ip,
                "transport": transport,
                "sport": sport,
                "dport": dport,
                "protocols": protocols,
                "summary": pkt.summary(),
            })

    if do_dns:
        for ip in hosts:
            hosts[ip]["dns_name"] = resolve_name(ip)

    return hosts, conversations, ot_findings


def host_records(hosts):
    records = []
    for ip, data in sorted(hosts.items()):
        records.append({
            "ip": ip,
            "dns_name": data["dns_name"] or "",
            "macs": sorted(data["macs"]),
            "vendors": sorted(data["vendors"]),
            "sent": data["sent"],
            "received": data["received"],
            "ports": dict(data["ports"]),
            "protocols": dict(data["protocols"]),
            "ot_protocols": dict(data["ot_protocols"]),
            "role_hints": sorted(data["role_hints"]),
        })
    return records


def conversation_records(conversations):
    records = []
    for (src, dst, transport, sport, dport), count in conversations.most_common():
        records.append({
            "src": src,
            "dst": dst,
            "transport": transport,
            "sport": sport,
            "dport": dport,
            "packets": count,
        })
    return records


def export_json(path, hosts, conversations, ot_findings):
    data = {
        "hosts": host_records(hosts),
        "conversations": conversation_records(conversations),
        "ot_findings": ot_findings,
    }
    Path(path).write_text(json.dumps(data, indent=2))


def export_csv(prefix, hosts, conversations, ot_findings):
    prefix = Path(prefix)

    with open(prefix.with_name(prefix.name + "_hosts.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "ip", "dns_name", "macs", "vendors", "sent", "received",
            "ports", "protocols", "ot_protocols", "role_hints"
        ])
        writer.writeheader()
        for rec in host_records(hosts):
            row = rec.copy()
            for key in ("macs", "vendors", "role_hints"):
                row[key] = "; ".join(row[key])
            for key in ("ports", "protocols", "ot_protocols"):
                row[key] = json.dumps(row[key])
            writer.writerow(row)

    with open(prefix.with_name(prefix.name + "_conversations.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "src", "dst", "transport", "sport", "dport", "packets"
        ])
        writer.writeheader()
        writer.writerows(conversation_records(conversations))

    with open(prefix.with_name(prefix.name + "_ot_findings.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "src", "dst", "transport", "sport", "dport", "protocols", "summary"
        ])
        writer.writeheader()
        for finding in ot_findings:
            row = finding.copy()
            row["protocols"] = "; ".join(row["protocols"])
            writer.writerow(row)


def print_report(hosts, conversations, ot_findings, top_n=20):
    print("\n=== Hosts Found ===\n")

    for ip, data in sorted(hosts.items()):
        print(ip)
        if data["dns_name"]:
            print(f"  DNS:        {data['dns_name']}")
        print(f"  MACs:       {', '.join(sorted(data['macs'])) or 'N/A'}")
        print(f"  Vendors:    {', '.join(sorted(data['vendors'])) or 'N/A'}")
        print(f"  Sent:       {data['sent']}")
        print(f"  Received:   {data['received']}")
        print(f"  Ports:      {', '.join(str(p) for p, _ in data['ports'].most_common(10)) or 'N/A'}")
        print(f"  Protocols:  {', '.join(f'{k}({v})' for k, v in data['protocols'].most_common()) or 'N/A'}")
        print(f"  OT Traffic: {', '.join(f'{k}({v})' for k, v in data['ot_protocols'].most_common()) or 'None'}")
        print(f"  Role Hints: {', '.join(sorted(data['role_hints'])) or 'None'}")
        print()

    print("\n=== Top Conversations ===\n")
    for rec in conversation_records(conversations)[:top_n]:
        ports = ""
        if rec["sport"] or rec["dport"]:
            ports = f" {rec['sport']}->{rec['dport']}"
        print(f"{rec['src']} -> {rec['dst']} [{rec['transport']}{ports}] : {rec['packets']} packets")

    print("\n=== OT / ICS Findings ===\n")
    if not ot_findings:
        print("No common OT/ICS traffic detected.")
        return

    for finding in ot_findings[:top_n]:
        ports = ""
        if finding["sport"] or finding["dport"]:
            ports = f" {finding['sport']}->{finding['dport']}"
        print(f"{finding['src']} -> {finding['dst']} [{finding['transport']}{ports}] {', '.join(finding['protocols'])}")


def main():
    parser = argparse.ArgumentParser(
        description="Passive PCAP parser for hosts, conversations, and common OT/ICS traffic."
    )
    parser.add_argument("pcap", help="Path to PCAP/PCAPNG file")
    parser.add_argument("--dns", action="store_true", help="Attempt reverse DNS lookups")
    parser.add_argument("--top", type=int, default=20, help="Number of conversations/findings to print")
    parser.add_argument("--json", dest="json_path", help="Export full results to JSON")
    parser.add_argument("--csv-prefix", help="Export CSV files using this output prefix")
    args = parser.parse_args()

    hosts, conversations, ot_findings = parse_pcap(args.pcap, args.dns)
    print_report(hosts, conversations, ot_findings, args.top)

    if args.json_path:
        export_json(args.json_path, hosts, conversations, ot_findings)
        print(f"\n[+] Wrote JSON: {args.json_path}")

    if args.csv_prefix:
        export_csv(args.csv_prefix, hosts, conversations, ot_findings)
        print(f"[+] Wrote CSV files with prefix: {args.csv_prefix}")


if __name__ == "__main__":
    main()
