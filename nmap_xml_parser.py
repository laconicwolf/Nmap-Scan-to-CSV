import xml.etree.ElementTree as etree
import os
import csv
import argparse
from collections import Counter
from sys import version
from time import sleep


if not version.startswith('3'):
    print('\nThis script is inteded to be run with Python3. If using another version and encounter an error, try using Python3\n')
    sleep(3)


__author__ = 'Jake Miller (@LaconicWolf)'
__date__ = '20171220'
__version__ = '0.01'
__description__ = '''Parses the xml output from an nmap scan. The user
                     can specify whether the data should be printed,
                     displayed as a list of IP addresses, or output to
                     a csv file. Will append to a csv if the filename
                     already exists'''


def get_xml_root(xml):
    """ Parses an xml file and returns the tree
    """
    tree = etree.parse(xml)
    root = tree.getroot()

    return root


def get_host_data(root):
    """ Goes through the xml tree and build lists of scan information
    and returns a list of lists.
    """
    host_data = []
    hosts = root.findall('host')
    for host in hosts:
        if not host.findall('status')[0].attrib['state'] == 'up':
            continue

        ip_address = host.findall('address')[0].attrib['addr']
        host_name_element = host.findall('hostnames')

        try:
            host_name = host_name_element[0].findall('hostname')[0].attrib['name']
        except IndexError:
            host_name = ''

        try:
            os_element = host.findall('os')
            os_name = os_element[0].findall('osmatch')[0].attrib['name']
        except IndexError:
            os_name = ''
        
        port_element = host.findall('ports')
        ports = port_element[0].findall('port')
        
        for port in ports:
            port_data = []
            if not port.findall('state')[0].attrib['state'] == 'open':
                continue

            proto = port.attrib['protocol']
            port_id = port.attrib['portid']
            service = port.findall('service')[0].attrib['name']

            try:
                product = port.findall('service')[0].attrib['product']
            except (IndexError, KeyError):
                product = ''
                               
            try:
                servicefp = port.findall('service')[0].attrib['servicefp']
            except (IndexError, KeyError):
                servicefp = ''

            try:
                script_id = port.findall('script')[0].attrib['id']
            except (IndexError, KeyError):
                script_id = ''

            try:
                script_output = port.findall('script')[0].attrib['output']
            except (IndexError, KeyError):
                script_output = ''

            port_data.extend((ip_address, host_name, os_name, proto, port_id, service, product, servicefp, script_id, script_output))
            host_data.append(port_data)
    
    return host_data


def parse_xml(filename):
    """ Calls functions to read the xml and extract elements and values
    """
    root = get_xml_root(filename)
    hosts = get_host_data(root)
    
    return hosts


def parse_to_csv(data):
    """Accepts a list and adds the items to (or creates) a CSV file.
    """
    if not os.path.isfile(csv_name):
        csv_file = open(csv_name, 'w', newline='')
        csv_writer = csv.writer(csv_file)
        top_row = ['IP', 'Host', 'OS', 'Proto', 'Port', 'Service', 'Product', 'Service FP', 'NSE Script ID', 'NSE Script Output', 'Notes']
        csv_writer.writerow(top_row)
        print('\n [+]  The file {} does not exist. New file created!\n'.format(csv_name))
    else:
        try:
            csv_file = open(csv_name, 'a', newline='')
        except PermissionError:
            print("\n [-]  Permission denied to open the file {}. Check if the file is open and try again.\n".format(csv_name))
            print("Print data to the terminal:\n")
            for item in data:
                print(' '.join(item))
            exit()
        csv_writer = csv.writer(csv_file)
        print('\n [+]  {} exists. Appending to file!\n'.format(csv_name))
    
    for item in data:
        csv_writer.writerow(item)
        
    csv_file.close()        


def list_ip_addresses(data):
    """ Parses the input data to display only the IP address information
    """
    ip_list = []
    for item in data:
        ip_list.append(item[0])
    sorted_set = sorted(set(ip_list))
    for ip in sorted_set:
        print(ip)


def least_common_ports(data, n):
    """ Examines the port index from data and returns the least common ports
    """
    n = int(n)
    c = Counter()
    for item in data:
        port = item[4]
        c.update([port])

    print("{0:8} {1:15}\n".format('PORT', 'OCCURENCES'))
    for p in c.most_common()[:-n-1:-1]:
        print("{0:5} {1:8}".format(p[0], p[1]))


def most_common_ports(data, n):
    """ Examines the port index from data and returns the most common ports
    """
    n = int(n)
    c = Counter()
    for item in data:
        port = item[4]
        c.update([port])

    print("{0:8} {1:15}\n".format('PORT', 'OCCURENCES'))
    for p in c.most_common(n):
        print("{0:5} {1:8}".format(p[0], p[1]))


def print_data(data):
    """ Prints the data to the terminal
    """
    for item in data:
        print(' '.join(item))


def main():
    for filename in args.filename:
        data = parse_xml(filename)
        if args.csv:
            parse_to_csv(data)
        if args.ip_addresses:
            list_ip_addresses(data)
        if args.print_all:
            print_data(data)
        if args.least_common_ports:
            print("\n{} LEAST COMMON PORTS".format(filename.upper()))
            least_common_ports(data, args.least_common_ports)
        if args.most_common_ports:
            print("\n{} MOST COMMON PORTS".format(filename.upper()))
            most_common_ports(data, args.most_common_ports)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--print_all", help="display scan information to the screen", action="store_true")
    parser.add_argument("-ip", "--ip_addresses", help="display a list of ip addresses", action="store_true")
    parser.add_argument("-csv", "--csv", nargs='?', const='scan.csv', help="specify the name of a csv file to write to. If the file already exists it will be appended")
    parser.add_argument("-f", "--filename", nargs='*', help="specify a file containing the output of an nmap scan in xml format.")
    parser.add_argument("-lc", "--least_common_ports", help="displays the least common open ports.")
    parser.add_argument("-mc", "--most_common_ports", help="displays the most common open ports.")
    args = parser.parse_args()

    if not args.filename:
        parser.print_help()
        print("\n [-]  Please specify an input file to parse. Use -f <nmap_scan.xml> to specify the file\n")
        exit()

    if not args.ip_addresses and not args.csv and not args.print_all and not args.least_common_ports and not args.most_common_ports:
        parser.print_help()
        print("\n [-]  Please choose an output option. Use -csv, -ip, or -p\n")
        exit()

    csv_name = args.csv
    main()