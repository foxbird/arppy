# ARPPY
## What is it?
Arppy is not, despite it's name, a python ARP utility of any variety. It does
have to do with ARP processing, but it's also made somewhat cute to sound like
a fox noise of some variety.

It's a C program that will listen on a given interface for ARP request packets,
check if they match a predefined list of target IP addresses and then respond 
with an ARP reply specifying either the interface's MAC address or one provided.
You can think of it like a form of proxy-arp, but without checking if the proxy
is on the other side of the device.

## Background
Why would you even need this, you might ask? Well, in a lot of cases 
(specifically Time Warner/Spectrum), if you have a block of public IP addresses,
their modem/router will always want to be the one handling the routable public
network addresses. If you want to apply access control you either need to use 
their device, or create a bridge between two ethernet ports and then apply 
access control there, also called a transparent bridge, or even simpler, a 
firewall. You might also be able to get away with dropping an interface in the 
public space provided by their router and do some form of (S/D)NAT as well, 
which is arguably a good way to go about it as well.

However, the device I'm using is a UniFi Dream Machine, which does not currently
support configurable NAT, and its method of matching public IP's to private ones
currently would require a bunch of individual VLAN's for each connection, a
subnet for each, and so on. It's very very messy.

## Diagram
What does a setup like this look like? Well, something like this:
```
                               192.168.100.0/24         192.168.100.0/24
                                   .1     ??             .1     .2-.254
[ISP Network] --- [ISP Device/Router] --- [Gateway (Arppy)] --- [Devices]
           .1     .2               .1     .2
         172.16.0.0/16         192.168.250.0/24
```

In this case, let's assume that the ISP has granted you a block of public routed
IP's of the form `192.168.100.0/24` (yes, these are not public, work with me).
The ISP device takes `192.168.100.1` for its own use. On its own public side, it
may have acquired `172.16.0.2` for it's own public address from the pool. If we
want `192.168.100.2` to be a devices in that devices block, we should put
the router address as `192.168.100.1` on the gateway's device-facing port. While
we CAN do that, and our gateway will happily accept packets for it, we can't
forward them to the ISP device readily, since we haven't given it another
address beyond what the public block is. Usually the modem/router will have some
private address as well (let's assume it's `192.168.250.1`) for you to talk to
the device and configure it. And sometimes it'll even do DHCP and such as well
as routing that public block. So, now we can make our Gateway's ISP facing port
have `192.168.250.2`, and the outgoing route would be `192.168.250.1`. So, now
we can send packets out. This is a good first step! 

The problem is, the ISP device is expecting `192.168.100.2` and all the other
devices to be directly connected to that device. But, it's not. It would be
nice if the Gateway would proxy arp itself. If it did, then it could respond
with it's ISP-facing MAC address when queried for any device on the inside.
However, in the case of the UniFi, it doesn't seem that it's doing so. It may
be that I just missed some critical configuration somewhere, but I can't make
it work easily. If you can get it to proxy-arp, you don't need this program!
There are some edge cases where the ISP device might try to arp its own IP and
that would get proxied and get a response, perhaps even blacklisted by the 
device. In which case, you may need to apply some access rules and the like to
prevent such things.

In my case, I need to tell the ISP device that the gateway is indeed the
interface attached to it, and that `192.168.100.2-192.168.100.254` is reachable
at the gateway device's interface. If I can convince the ISP's device that the
interface is attached, it will forward the packets there. And the gateway, would
then continue to route them along to the real device inside. Replies would
already work because we have a private IP to talk over and that private IP uses
the same MAC address as the one we want the ISP's device to use. How do we
do this?

In comes Arrpy! You tell it to listen on that interface between the ISP device
and the gateway itself, give it a list of IP's (`192.168.100.2-192.168.100.254`
in our case), and then arrpy will generate an ARP reply to the incoming request
with the MAC address of the gateway. Now, packets can flow!

## How does it work?
Take a gander at the source code. It's fairly simple. It opens a PF_PACKET raw
socket, specifying that it wants ARP only, then as a double-measure it applies
a BPF (packet filter) to only get ARP (you may find that you need to change the
`ETH_P_ARP` to `ETH_P_ALL` if for some reason you aren't getting ARP packets,
in which case the BPF filter is totally needed), and then it sends a raw packet
of its own out of the device.

## Building
To build it, you just need to invoke `configure`, and then `make`. If you're
cross-compiling, remember to do something like this:
```
arppy$ ./configure --host aarch64-linux-gnu LDFLAGS="-static"
```
In this case, we added `-static` since the version of GLIC on the device may not
be the same as what we have on our host. If you know how to work around that, I
would love a PR!

Also, I am not a wizard with `autoconf` or `automake`. This is the first time I
even tried using them in a project. I probably haven't done any of it good
justice, so if you know more and want to take a whack at it, please give me a PR
for it.

## Running
Arrpy will give you some help with `--help` argument.
```
Usage: arppy [OPTION...] INTERFACE IPS
Arp responder for limited proxy-arping

  -c, --config=FILE          Configuration file
  -d, --dry-run              Do not send arp replies
  -m, --mac=MACADDRSS        MAC to send (eeee.eeee.eeee)
  -v, --verbose              Verbose output (specify multiple times for more
                             verbosity)
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.
```

* config - That's not implemented. I wanted to read the arguments from a config-
like file, but I couldn't really be bothered to also write a parser for that. So
the stub is in there, but it's not implemented.
* dry-run - Don't actually send anything. You can use this sto see what WOULD be
sent if you turned it on. Very useful with two verbose flags. Maybe three, if
you need them.
* mac - Don't want to use the MAC address of the interface you're listening on?
Then this option is for you! Specify whatever MAC address you want. Be careful
though, as I'm not sure all kernels, network drivers, etc will send packets for
mac's that aren't you. If you don't specify, it'll get the MAC from the
interface you bound to.
* verbose - You can specify this up to three times (more if you want). At the
first level, it'll print some diagnostic information during startup to make
sure everything you configured is correct. At the second level, it'll show you
the incoming and outgoing packets its creating. And at the third level, it'll
dump out any incoming arp replies as well. 
* INTERFACE - The name of your interface to bind to. Something like `eth1` or
`ensp32` or something.
* IPS - A comma separated list of IP addresses ot listen to. This doesn't do 
anything with lists or similar, so if you have a LOT of IP's to handle, you will
totally need to list them all out. Or, submit a PR to support parsing lists and
the like.

You will need to run this as root, or somehow bless the app to allow it to get a
raw socket. 

## Other Considerations
You could run this on a device OTHER than your gateway. If you have a tiny PC of
some kind (say a raspberry PI or something), you could run the app there, but
then speicfy the `-m` option to give it a different mac to respond. In which
case you'd give it the MAC address of your gateway device.

## Bugs?
I wouldn't doubt if there are some. This was for my own use, so I didn't write
tests, but I did do a lot of debugging, testing, and running it on my actual
device, and it all seems fine. It's got a very low memory footprint, doesn't
seem to each up much CPU (thanks for the selective socket and BPF), so it should
be fairly safe to run. Feel free to give me a PR if you find any want to improve
things.

## Example Output
```
root@gateway:~# ./arppy -v -v eth9 192.168.100.2,192.168.100.3
verbosity: 2
Listening for IP 192.168.100.2
Listening for IP 192.168.100.3
mac address for replies: e7d3.c4d8.41e6
setting bpf filter for data
Request: Who has 192.168.100.10, tell 192.168.100.1 (9bc3.3333.18d7)
Request: Who has 192.168.100.10, tell 192.168.100.1 (9bc3.3333.18d7)
Request: Who has 192.168.100.5, tell 192.168.100.1 (9bc3.3333.18d7)
Request: Who has 192.168.100.4, tell 192.168.100.1 (9bc3.3333.18d7)
Request: Who has 192.168.100.7, tell 192.168.100.1 (9bc3.3333.18d7)
Request: Who has 192.168.100.12, tell 192.168.100.1 (9bc3.3333.18d7)
Request: Who has 192.168.100.2, tell 192.168.100.1 (9bc3.3333.18d7)
Send Reply: Tell 192.168.100.1 (9bc3.3333.18d7), 192.168.100.12 is at e7d3.c4d8.41e6
```
