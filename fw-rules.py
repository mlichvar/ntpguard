#!/usr/bin/python3
# Copyright (C) 2025  Miroslav Lichvar <mlichvar0@gmail.com>
# SPDX-License-Identifier: GPL-2.0-or-later

import ipaddress
import optparse
import sys

nets = {}

def get_sorted_nets():
    return sorted(nets.keys(), reverse=True, key = lambda np: nets[np])

parser = optparse.OptionParser(usage="Usage: %prog [OPTION]... LOGFILE...",
                               description="Prepare firewall rules from detector logs")
parser.add_option("-n", "--max-nets", dest="max_nets", type="int", default=20,
                  help="set maximum number of blocked networks (20)")
parser.add_option("-p", "--min-prefix", dest="min_prefix", type="int", default=16,
                  help="set minimum network prefix length (16)")
parser.add_option("-c", "--coverage", dest="coverage", type="float", default=80,
                  help="set target rate coverage in % (80)")
parser.add_option("-i", "--ignore-client", dest="ignored_client", action="append", default=[],
                  help="ignore client type")
parser.add_option("-x", "--intersect", dest="intersect", action="store_true", default=False,
                  help="ignore addresses not present in all log files")

(options, paths) = parser.parse_args()

if len(paths) == 0:
    parser.print_help()
    sys.exit(1)

total_weight = 0
input_nets = []
clients = {}
for path in paths:
    input_nets.append(set())
    with open(path, "r") as f:
        for line in f:
            tokens = line.split()
            net = ipaddress.ip_network(ipaddress.ip_address(tokens[1]))
            port = int(tokens[2].split('=')[1])
            rate = int(tokens[3].split('=')[1])
            client = tokens[4].split('=')[1] if len(tokens) > 4 else "?"

            if client in options.ignored_client:
                continue

            if client == "timesyncd":
                port = -1 # dynamic port

            if (net, port) not in nets:
                nets[(net, port)] = 0
            nets[(net, port)] += rate
            total_weight += rate
            input_nets[-1].add((net, port))
            clients[(net, port)] = client

if options.intersect:
    common = set.intersection(*input_nets)
    for np in nets.keys() - common:
        nets.pop(np)

all_input_nets = set.union(*input_nets)

for prefix in range(31, options.min_prefix - 1, -1):
    sorted_nets = get_sorted_nets()
    sum_weight = sum([nets[np] for np in sorted_nets[:options.max_nets]])
    if sum_weight > options.coverage / 100 * total_weight:
        break

    new_nets = {}
    processed_nets = set()
    for net_port in sorted_nets:
        net, port = net_port
        if net_port not in nets:
            continue
        processed_nets.add(net_port)
        supnet = net.supernet(new_prefix=prefix)
        matches = [(np, nets[np]) for np in nets if supnet.supernet_of(np[0]) \
                    and np[1] == port]
        if len(matches) > 1:
            sum_weight = 0
            for match in matches:
                processed_nets.add(match[0])
                nets.pop(match[0])
                sum_weight += match[1]
            nets[(supnet, port)] = sum_weight

sum_all_addrs = 0
sum_match_addrs = 0
sum_weight = 0
print("Rule     Network          Port     Rate   Specif.  False    Clients")
for i, np in enumerate(get_sorted_nets()[:options.max_nets]):
    weight = nets[np]
    all_addrs = np[0].num_addresses 
    match_addrs = 0
    net_clients = set()
    for np2 in all_input_nets:
        if np2[0].subnet_of(np[0]) and np2[1] == np[1]:
            net_clients.add(clients[np2])
            match_addrs += 1

    sum_weight += nets[np]
    sum_all_addrs += all_addrs
    sum_match_addrs += match_addrs
    
    print("{:3d} {:18s}   {:5d}   {:5.1f}%   {:5.1f}% {:7d}  {}".format(i + 1, str(np[0]), np[1],
          weight / total_weight * 100, match_addrs / all_addrs * 100, all_addrs - match_addrs,
          '+'.join(net_clients)))

print("SUM                              {:5.1f}%   {:5.1f}% {:7d}".format(
      sum_weight / total_weight * 100, sum_match_addrs / sum_all_addrs * 100,
      sum_all_addrs - sum_match_addrs))
