import csv
import os

class Firewall(object):

    # array of rules
    # ex: [{direction: inbound, protocol: udp, etc...}, {}]
    rules = []

    # creates a new firewall with rules parsed from a csv file at path
    def __init__(self, path):

        if os.path.exists(path):
            reader = csv.reader(open(path, 'r'))

            # go to second line in file
            next(reader)

            for row in reader:
                rule = {'direction' : row[0], 'protocol': row[1], 'port': row[2], 'ip': row[3]}

                # replace ranges with list of min and max values
                if('-' in rule['port']):
                    rule['port'] = rule['port'].split('-')

                if('-' in rule['ip']):
                    rule['ip'] = rule['ip'].split('-')

                self.rules.append(rule)
            print(self.rules)

        else:
            print('Error, file not found!')

    # converts ipv4 formatted string to its integer value
    def convert_ipv4(self, ip):
            return tuple(int(n) for n in ip.split('.'))

    # accepts network packet
    # returns true if a rule matching packet arguments is found
    # otherwise returns false
    def accept_packet(self, direction, protocol, port, ip):
        for rule in self.rules:

            if(rule['direction'] == direction and rule['protocol'] == protocol):
                valid_ip = False
                valid_port = False

                if(isinstance(rule['port'], list)):
                    if(int(rule['port'][0]) <= int(port) <= int(rule['port'][1])):
                        valid_port = True
                else:
                    if(port == rule['port']):
                        valid_port = True

                if(isinstance(rule['ip'], list)):
                    if(self.convert_ipv4(rule['ip'][0]) <= self.convert_ipv4(ip) <= self.convert_ipv4(rule['ip'][1])):
                        valid_ip = True
                else:
                    if(ip == rule['ip']):
                        valid_ip = True

                if(valid_ip == True and valid_port == True):
                    return True

        return False

def main():
    firewall = Firewall('fw.txt')

    # test blocked packets
    print(firewall.accept_packet('inbound', 'udp', '80', '192.168.1.2'))
    print(firewall.accept_packet('outbound', 'tcp', '80', '192.168.1.2'))
    print(firewall.accept_packet('inbound', 'tcp', '80', '192.168.1.3'))

    # test allowed packets
    print(firewall.accept_packet('inbound', 'tcp', '80', '192.168.1.2'))

    # test allowed packets with ips within range of rule
    print(firewall.accept_packet('inbound', 'udp', '53', '192.168.1.1'))
    print(firewall.accept_packet('inbound', 'udp', '53', '192.168.1.3'))
    print(firewall.accept_packet('inbound', 'udp', '53', '192.168.2.3'))
    print(firewall.accept_packet('inbound', 'udp', '53', '192.168.2.4'))
    print(firewall.accept_packet('inbound', 'udp', '53', '192.168.2.5'))

    # test blocked packets with ips just outside range
    print(firewall.accept_packet('inbound', 'udp', '53', '192.168.1.0'))
    print(firewall.accept_packet('inbound', 'udp', '53', '192.168.2.6'))

    # test allowed packets with ports within range of rule
    print(firewall.accept_packet('outbound', 'tcp', '10000', '192.168.10.11'))
    print(firewall.accept_packet('outbound', 'tcp', '12020', '192.168.10.11'))
    print(firewall.accept_packet('outbound', 'tcp', '20000', '192.168.10.11'))

    # test blocket packets with ports just outside range
    print(firewall.accept_packet('outbound', 'tcp', '9999', '192.168.10.11'))
    print(firewall.accept_packet('outbound', 'tcp', '20001', '192.168.10.11'))

    # test packets with port and ip inside of ranges
    print(firewall.accept_packet('outbound', 'udp', '1000', '52.12.48.92'))
    print(firewall.accept_packet('outbound', 'udp', '1202', '52.12.49.92'))
    print(firewall.accept_packet('outbound', 'udp', '1202', '52.12.50.9'))
    print(firewall.accept_packet('outbound', 'udp', '2000', '52.12.50.92'))

    # test packets with port just outside of range and ip with in range
    print(firewall.accept_packet('outbound', 'udp', '999', '52.12.48.92'))
    print(firewall.accept_packet('outbound', 'udp', '2001', '52.12.50.92'))

    # test packet with ip just outside of range and port with in range
    print(firewall.accept_packet('outbound', 'udp', '999', '52.12.47.91'))
    print(firewall.accept_packet('outbound', 'udp', '999', '52.12.48.91'))
    print(firewall.accept_packet('outbound', 'udp', '2001', '52.12.50.93'))

if __name__ == "__main__":
    main()
