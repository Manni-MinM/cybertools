import argparse

from scanner import Scanner


parser = argparse.ArgumentParser(description="IP Scanner")

parser.add_argument("--ipscan", action="store_true", required=False)
parser.add_argument("-ip", required=False, nargs=2)

parser.add_argument("--portscan", action="store_true", required=False)
parser.add_argument("-tcp", required=False, nargs=2, type=int)
parser.add_argument("-udp", required=False, nargs=2, type=int)

args = parser.parse_args()

if args.ipscan:
    Scanner.ip_scan(args.ip[0], args.ip[1])

elif args.portscan:
    if args.tcp is not None:
        Scanner.scan_ports(
            args.ip[0],
            args.ip[1],
            args.tcp[0],
            args.tcp[1],
            "tcp",
        )

    elif args.udp is not None:
        Scanner.scan_ports(
            args.ip[0],
            args.ip[1],
            args.udp[0],
            args.udp[1],
            "udp",
        )
