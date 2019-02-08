#!/usr/bin/env python

import scapy.all as scapy
import optparse

def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest='ip', help="Select a target IP Address")
    (options, arguments) = parser.parse_args()
    if not options.ip:
        parser.error("[-] Please specify an ip address you would like to scan.  Use --help for more info")
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for i in answered_list:
        client_dict = {
            'ip': i[1].psrc,
            'mac': i[1].hwsrc
        }
        clients_list.append(client_dict)
    return (clients_list)

def print_results(list):
    print("IP\t\t\tMAC Address\n-----------------------------------")
    for i in list:
        print("{0}\t\t{1}".format(i["ip"], i["mac"]))

options = get_args()
print_results(scan(options.ip + "/24"))


