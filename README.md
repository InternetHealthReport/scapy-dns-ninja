DNS rendez-vous point for measurement infrastructures (like RIPE Atlas) to probe multiple IPs.

# IHR instance

The current IHR instance is at content.ninja.ihr.live which is queried by all RIPE Atlas probes (measurement ID [44852121](https://atlas.ripe.net/measurements/44852121)) and resolves to the domains listed in [content/dests.cnames.txt](https://github.com/InternetHealthReport/scapy-dns-ninja/blob/master/content/dests.cnames.txt).

See also: https://github.com/RIPE-Atlas-Community/ripe-atlas-tips-and-tricks/wiki/PopularContent

Feel free to ask for additional domains by [creating a new issue](https://github.com/InternetHealthReport/scapy-dns-ninja/issues/).


# Deploy your own
## Installation

Create a *ninja-server.conf* file, as explained below, and then run the ./dns-ninja-server.py process. Because this doesn't listen on a UDP port, but sniffs traffic coming in, care should be taken not to send out ICMP destination unreachable messages. For example, Linux/iptables:
    iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP


## Configuration

Needs a local config file called 'ninja-server.conf' in yaml format. Example:

    ---
    ServerIP: 192.168.0.1
    ServerDomain: random-ip.emileaben.com

This code acts as a DNS server, and when it receives an A or AAAA request it returns an IP address from a specified list.

For DNS A queries lists are called *dests.v4.txt*, for AAAA queries *dests.v6.txt*. If both of these don't exist but a file called *dests.cnames.txt* exists, this file will be used and will generate CNAME redirects towards the hostnames in this file.

If the server is queried for a label in this form:

    <listname>.<serverdomain>

it will try to find a dests.v[46].txt file in the local <listname> directory, and serve IPs from there.
If there is no match it will use the IP-lists file(s) in the `_default` directory.

example (with config file above):

query for amsterdam-nl.random-ip.emilaben.com

will cause the server to look for an ip-list file (either dests.v[46].txt) in the local ./amsterdam-nl/ directory. If it exists it will load it, randomize the list, and serve an IP from it. The next query for this name will get the next IP from the randomized list.
At the end of the list, it will be randomized again, and the first IP from the randomized list will be returned again.
