import socket
import icmplib
import ipaddress


class Scanner:
    @staticmethod
    def log(msg, fp=None):
        if fp:
            fp.write(f"{msg}\n")
        print(msg)

    @staticmethod
    def ip_range(start_ip, end_ip):
        to_int = lambda x: int(ipaddress.IPv4Address(x))
        return [ipaddress.IPv4Address(ip) for ip in range(to_int(start_ip), to_int(end_ip) + 1)]

    @staticmethod
    def heartbeat(ip_address):
        return icmplib.ping(str(ip_address), count=3, interval=0.05).is_alive

    @staticmethod
    def ip_scan(start_ip, end_ip):
        live_hosts = []
        with open("icmp_result.txt", "w") as file:
            ip_range = Scanner.ip_range(start_ip, end_ip)

            for ip in ip_range:
                if Scanner.heartbeat(ip):
                    live_hosts.append(ip)

                Scanner.log(f"Host: {ip} is {'Up' if Scanner.heartbeat(ip) else 'Down'}", file)

        return live_hosts

    @staticmethod
    def get_service_name(port, protocol):
        try:
            return socket.getservbyport(port, protocol.lower())
        except Exception:
            return "Error: cannot retrieve service name"

    @staticmethod
    def scan_ports(start_ip, end_ip, start_port, end_port, protocol_mode):
        live_hosts = Scanner.ip_scan(start_ip, end_ip)

        socket_type = socket.SOCK_DGRAM if protocol_mode == "udp" else socket.SOCK_STREAM

        with open(f"{protocol_mode}_result.txt", "w") as file:
            for target in live_hosts:
                for port in range(start_port, end_port + 1):
                    sock = socket.socket(socket.AF_INET, socket_type)
                    sock.settimeout(0.5)

                    result = sock.connect_ex((str(target), port))

                    if result == 0:
                        Scanner.log(
                            f"Proto: {protocol_mode} | Host: {target} | Port: {port} | App: {Scanner.get_service_name(port, protocol_mode)}",
                            file,
                        )

                    else:
                        Scanner.log(
                            f"Proto: {protocol_mode} | Host: {target} | Port: {port} is Unavailable",
                            file,
                        )

                    sock.close()
