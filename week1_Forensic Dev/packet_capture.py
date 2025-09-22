import sys
from scapy.layers.inet import ICMP, TCP, UDP, IP
from scapy.all import *

count = 1
protocols = {1: 'icmp', 6: 'tcp', 17: 'udp'}

protocol_type = input("Protocol Type (icmp/tcp/udp): ")
sniffing_time = input("Sniffing Time (seconds): ")

def sniffing():
    print("\n[+] Sniffing Start...")
    pcap_file = sniff(prn=showPacket, timeout=int(sniffing_time), filter=str(protocol_type))
    print("[+] Finish Capture Packet")

    global count
    if count == 1:
        print("[!] No Packet Captured")
        sys.exit(0)
    else:
        print(f"[+] Total Packet Captured: {count-1}")
        file_name = input("Enter File Name to Save (.pcap): ")
        wrpcap(str(file_name), pcap_file)
        print(f"[+] Saved as {file_name}")

def showPacket(packet):
    global count

    # IP 계층 정보
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    ttl = packet[IP].ttl
    length = packet[IP].len

    if proto in protocols:
        proto_name = protocols[proto].upper()

        # ICMP
        if proto == 1:
            message_type = packet[ICMP].type
            code = packet[ICMP].code
            print(f"[{count}] {proto_name} | {src_ip} -> {dst_ip} | TTL={ttl} Len={length}")
            print(f"    Type={message_type} Code={code}\n")

        # TCP
        elif proto == 6:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            seq = packet[TCP].seq
            ack = packet[TCP].ack
            flag = packet[TCP].flags
            print(f"[{count}] {proto_name} | {src_ip}:{sport} -> {dst_ip}:{dport}")
            print(f"    TTL={ttl} Len={length} Seq={seq} Ack={ack} Flags={flag}\n")

        # UDP
        elif proto == 17:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            udp_length = packet[UDP].len
            print(f"[{count}] {proto_name} | {src_ip}:{sport} -> {dst_ip}:{dport}")
            print(f"    TTL={ttl} PacketLen={udp_length}\n")

        count += 1  # 모든 프로토콜에서 공통으로 카운트 증가

# 프로그램 실행 부분
if __name__ == "__main__":
    if protocol_type in protocols.values():
        sniffing()
    else:
        print("Unsupported Format. Choose icmp/tcp/udp.")
