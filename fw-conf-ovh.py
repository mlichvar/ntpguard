#!/usr/bin/python3
# Copyright (C) 2025  Miroslav Lichvar <mlichvar0@gmail.com>
# SPDX-License-Identifier: GPL-2.0-or-later

import optparse
import ovh
import sys
import time

parser = optparse.OptionParser(usage="Usage: %prog [OPTION]... IP-ADDRESS...",
                               description="Manage OVH firewall for an NTP server")
parser.add_option("-m", "--mode", dest="mode", default="list",
                  help="select mode: token, list, delete, set (list)")
parser.add_option("-r", "--rule-file", dest="rule_file",
                  help="specify path to file containing rules in \"set\" mode")
parser.add_option("-f", "--first-index", dest="first_index", type="int", default=0,
                  help="specify index of first rule to operate on (0)")
parser.add_option("-l", "--last-index", dest="last_index", type="int", default=19,
                  help="specify index of last rule to operate on (19)")

(options, ip_addrs) = parser.parse_args()
allowed_indices = set(range(options.first_index, options.last_index + 1))

if (options.mode not in ["token", "list", "delete", "set"] or \
        len(ip_addrs) == 0 and options.mode != "token") or \
        (options.mode == "set" and options.rule_file is None):
    parser.print_help()
    sys.exit(1)

client = ovh.Client()

if options.mode == "token":
    ck = client.new_consumer_key_request()
    ck.add_recursive_rules(ovh.API_READ_WRITE, '/ip/*/firewall')

    validation = ck.request()
    print(f"Validate token {validation['consumerKey']} at:\n{validation['validationUrl']}")

if options.mode == "list":
    for ip in ip_addrs:
        print(f"Listing rules of {ip}:")
        for index in sorted(client.get(f"/ip/{ip}/firewall/{ip}/rule/")):
            if index not in allowed_indices:
                continue
            rule = client.get(f"/ip/{ip}/firewall/{ip}/rule/{index}")
            print(f"{index}: {rule['rule']}")

if options.mode in ("delete", "set"):
    for ip in ip_addrs:
        for index in sorted(client.get(f"/ip/{ip}/firewall/{ip}/rule/")):
            if index not in allowed_indices:
                continue
            print(f"Deleting rule {index} of {ip}")
            client.delete(f"/ip/{ip}/firewall/{ip}/rule/{index}")

    first_wait = True
    t = 5
    for ip in ip_addrs:
        while True:
            if len(set(client.get(f"/ip/{ip}/firewall/{ip}/rule/")) & allowed_indices) == 0:
                break
            if first_wait:
                print("Waiting...", end="", flush=True)
                first_wait = False
            else:
                print(".", end="", flush=True)
            time.sleep(t)
            t *= 1.2
    if not first_wait:
        print()

if options.mode == "set":
    for ip in ip_addrs:
        with open(options.rule_file, "r") as f:
            index = options.first_index - 1
            for line in f:
                tokens = line.strip().split()
                try:
                    int(tokens[0])
                except:
                    continue
                net = tokens[1]
                port = int(tokens[2])

                index += 1
                if index > options.last_index:
                    print("Warning: rule file contains more rules than allowed indices")
                    break

                print(f"Adding rule {index} of {ip} for {net}:{port}")
                client.post(f"/ip/{ip}/firewall/{ip}/rule",
                    action = "deny",
                    sourcePort = port if port >= 0 else None,
                    destinationPort = 123,
                    protocol = "udp",
                    sequence = index,
                    source = net
                )

        print(f"Enabling firewall {ip}")
        client.put(f"/ip/{ip}/firewall/{ip}", enabled = True)
