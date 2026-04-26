#!/usr/bin/env python3
"""
generate_sample_pcap.py

Creates a small synthetic PCAP for demonstrating pcap_ot_hosts.py.
The traffic is artificial and safe. It is intended for parser demos only.
"""

try:
    from scapy.all import Ether, IP, TCP, UDP, ARP, Raw, wrpcap
except ImportError:
    print("Missing dependency: scapy")
    print("Install with: pip install scapy")
    raise SystemExit(1)


def main():
    packets = []

    plc_mac = "00:1b:1b:10:20:30"      # Siemens-like OUI for demo
    hmi_mac = "00:80:f4:aa:bb:cc"      # Rockwell-like OUI for demo
    eng_mac = "00:15:64:11:22:33"      # Beckhoff-like OUI for demo
    bas_mac = "00:05:ba:44:55:66"      # Schneider-like OUI for demo

    plc = "192.168.10.10"
    hmi = "192.168.10.20"
    eng = "192.168.10.30"
    bas = "192.168.10.40"

    packets.append(Ether(src=hmi_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(psrc=hmi, pdst=plc))

    # Modbus/TCP request from HMI to PLC, function 3 read holding registers.
    modbus_payload = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x02"
    packets.append(Ether(src=hmi_mac, dst=plc_mac) / IP(src=hmi, dst=plc) /
                   TCP(sport=40100, dport=502, flags="PA") / Raw(load=modbus_payload))

    # Siemens S7comm / ISO-TSAP hint over TCP/102.
    packets.append(Ether(src=eng_mac, dst=plc_mac) / IP(src=eng, dst=plc) /
                   TCP(sport=40200, dport=102, flags="S"))

    # EtherNet/IP ListIdentity over TCP/44818.
    enip_list_identity = b"\x63\x00\x00\x00\x00\x00\x00\x00"
    packets.append(Ether(src=eng_mac, dst=hmi_mac) / IP(src=eng, dst=hmi) /
                   TCP(sport=40300, dport=44818, flags="PA") / Raw(load=enip_list_identity))

    # BACnet/IP demo packet.
    packets.append(Ether(src=hmi_mac, dst=bas_mac) / IP(src=hmi, dst=bas) /
                   UDP(sport=49000, dport=47808) / Raw(load=b"\x81\x0a\x00\x11demo-bacnet"))

    # OPC UA HEL message.
    packets.append(Ether(src=eng_mac, dst=hmi_mac) / IP(src=eng, dst=hmi) /
                   TCP(sport=40400, dport=4840, flags="PA") / Raw(load=b"HELdemo-opcua"))

    # Normal web traffic for contrast.
    packets.append(Ether(src=hmi_mac, dst=eng_mac) / IP(src=hmi, dst=eng) /
                   TCP(sport=50500, dport=443, flags="S"))

    wrpcap("sample_ot_demo.pcap", packets)
    print("Wrote sample_ot_demo.pcap")


if __name__ == "__main__":
    main()
