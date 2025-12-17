#!/usr/bin/env python3

import socket
import select
import sys
import time
import struct

ETH_P_ALL = 0x0003   # Capture all Ethernet protocols
LOG_FILE = "tap2_tap3_l2_l3_l4.log"


def open_iface(ifname: str):
    """
    Open a raw AF_PACKET socket on the given interface.
    Works with TAP interfaces used by GNS3.
    """
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((ifname, 0))
    return s


# ------------- L2 HELPERS -------------

def mac_to_str(mac_bytes: bytes) -> str:
    """Convert 6-byte MAC to human-readable string."""
    return ":".join(f"{b:02x}" for b in mac_bytes)


def parse_eth_header(frame: bytes):
    """
    Parse Ethernet header: dst MAC, src MAC, EtherType.
    Returns dict.
    """
    if len(frame) < 14:
        return None

    dst_mac = mac_to_str(frame[0:6])
    src_mac = mac_to_str(frame[6:12])
    ethertype = int.from_bytes(frame[12:14], byteorder="big")

    return {
        "dst_mac": dst_mac,
        "src_mac": src_mac,
        "ethertype": ethertype,
    }


def ethertype_to_name(ethertype: int) -> str:
    mapping = {
        0x0800: "IPv4",
        0x0806: "ARP",
        0x86DD: "IPv6",
        0x8100: "802.1Q VLAN",
    }
    return mapping.get(ethertype, f"0x{ethertype:04x}")


# ------------- L3 HELPERS (IPv4) -------------

def ip_to_str(ip_bytes: bytes) -> str:
    return ".".join(str(b) for b in ip_bytes)


def parse_ipv4_header(frame: bytes, offset: int = 14):
    """
    Parse IPv4 header starting at given offset (normally after Ethernet).
    Returns dict with header fields and header length in bytes, or None.
    """
    if len(frame) < offset + 20:
        return None

    ip_header = frame[offset:offset + 20]
    ver_ihl, tos, total_length, ident, flags_frag, ttl, proto, checksum, src, dst = struct.unpack(
        "!BBHHHBBH4s4s", ip_header
    )

    version = ver_ihl >> 4
    ihl = ver_ihl & 0x0F
    ip_header_len = ihl * 4

    if len(frame) < offset + ip_header_len:
        # malformed
        return None

    return {
        "version": version,
        "ihl": ihl,
        "tos": tos,
        "total_length": total_length,
        "id": ident,
        "flags_frag": flags_frag,
        "ttl": ttl,
        "protocol": proto,
        "checksum": checksum,
        "src_ip": ip_to_str(src),
        "dst_ip": ip_to_str(dst),
        "header_len_bytes": ip_header_len,
    }


def ip_proto_to_name(proto: int) -> str:
    mapping = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
    }
    return mapping.get(proto, str(proto))


# ------------- L4 HELPERS (TCP/UDP/ICMP) -------------

def parse_tcp_header(frame: bytes, offset: int):
    """
    Parse TCP header at given offset.
    Returns dict or None.
    """
    if len(frame) < offset + 20:
        return None

    tcp_header = frame[offset:offset + 20]
    src_port, dst_port, seq, ack, offset_reserved_flags, window, checksum, urg_ptr = struct.unpack(
        "!HHLLHHHH", tcp_header
    )

    data_offset = (offset_reserved_flags >> 12) & 0xF
    tcp_header_len = data_offset * 4
    flags = offset_reserved_flags & 0x3F  # FIN,SYN,RST,PSH,ACK,URG (6 bits)

    flag_names = []
    if flags & 0x01:
        flag_names.append("FIN")
    if flags & 0x02:
        flag_names.append("SYN")
    if flags & 0x04:
        flag_names.append("RST")
    if flags & 0x08:
        flag_names.append("PSH")
    if flags & 0x10:
        flag_names.append("ACK")
    if flags & 0x20:
        flag_names.append("URG")

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "data_offset": data_offset,
        "window": window,
        "checksum": checksum,
        "urg_ptr": urg_ptr,
        "flags_bits": flags,
        "flags": ",".join(flag_names) if flag_names else "NONE",
    }


def parse_udp_header(frame: bytes, offset: int):
    if len(frame) < offset + 8:
        return None

    udp_header = frame[offset:offset + 8]
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", udp_header)

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "checksum": checksum,
    }


def parse_icmp_header(frame: bytes, offset: int):
    if len(frame) < offset + 4:
        return None

    icmp_header = frame[offset:offset + 4]
    icmp_type, code, checksum = struct.unpack("!BBH", icmp_header)

    return {
        "type": icmp_type,
        "code": code,
        "checksum": checksum,
    }


# ------------- LOGGING -------------

def log_packet(if_in: str, if_out: str, frame: bytes):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")

    l2 = parse_eth_header(frame)
    if not l2:
        line = f"[{ts}] {if_in} -> {if_out}\nL2: <invalid ethernet frame len={len(frame)}>\n\n"
        with open(LOG_FILE, "a") as f:
            f.write(line)
        return

    ethertype_name = ethertype_to_name(l2["ethertype"])

    # Base log
    lines = []
    lines.append(f"[{ts}] {if_in} -> {if_out}")
    lines.append(
        f"L2: src_mac={l2['src_mac']} dst_mac={l2['dst_mac']} "
        f"ethertype={ethertype_name} (0x{l2['ethertype']:04x}) frame_len={len(frame)}"
    )

    # L3 / L4 only for IPv4
    if l2["ethertype"] == 0x0800:  # IPv4
        ip = parse_ipv4_header(frame, offset=14)
        if ip:
            proto_name = ip_proto_to_name(ip["protocol"])
            lines.append(
                "L3: IPv4 "
                f"src_ip={ip['src_ip']} dst_ip={ip['dst_ip']} "
                f"ttl={ip['ttl']} id={ip['id']} "
                f"ihl={ip['ihl']} total_len={ip['total_length']} "
                f"proto={proto_name}({ip['protocol']})"
            )

            l4_offset = 14 + ip["header_len_bytes"]
            l4_line = None

            if ip["protocol"] == 6:  # TCP
                tcp = parse_tcp_header(frame, l4_offset)
                if tcp:
                    l4_line = (
                        "L4: TCP "
                        f"sport={tcp['src_port']} dport={tcp['dst_port']} "
                        f"seq={tcp['seq']} ack={tcp['ack']} "
                        f"flags={tcp['flags']} window={tcp['window']}"
                    )

            elif ip["protocol"] == 17:  # UDP
                udp = parse_udp_header(frame, l4_offset)
                if udp:
                    l4_line = (
                        "L4: UDP "
                        f"sport={udp['src_port']} dport={udp['dst_port']} "
                        f"len={udp['length']}"
                    )

            elif ip["protocol"] == 1:  # ICMP
                icmp = parse_icmp_header(frame, l4_offset)
                if icmp:
                    l4_line = (
                        "L4: ICMP "
                        f"type={icmp['type']} code={icmp['code']}"
                    )

            if l4_line:
                lines.append(l4_line)
        else:
            lines.append("L3: <invalid IPv4 header>")

    # Write to file
    with open(LOG_FILE, "a") as f:
        f.write("\n".join(lines) + "\n\n")


# ------------- MAIN FORWARDER -------------

def main():
    if2 = "tap2"
    if3 = "tap3"

    print(f"[+] Opening raw sockets on {if2} and {if3}...")
    print(f"[+] Logging L2/L3/L4 to {LOG_FILE}")

    try:
        s2 = open_iface(if2)
        s3 = open_iface(if3)
    except OSError as e:
        print(f"[-] Error opening interfaces: {e}")
        sys.exit(1)

    print("[+] Successfully opened raw sockets.")
    print("[+] Forwarding frames tap2 <-> tap3 with full L2/L3/L4 logging (Ctrl+C to stop)")

    PKT_OUT = getattr(socket, "PACKET_OUTGOING", 4)

    try:
        while True:
            r, _, _ = select.select([s2, s3], [], [])

            # tap2 -> tap3
            if s2 in r:
                data, addr = s2.recvfrom(65535)
                pkttype = addr[2]
                if pkttype != PKT_OUT:
                    log_packet("tap2", "tap3", data)
                    s3.send(data)

            # tap3 -> tap2
            if s3 in r:
                data, addr = s3.recvfrom(65535)
                pkttype = addr[2]
                if pkttype != PKT_OUT:
                    log_packet("tap3", "tap2", data)
                    s2.send(data)

    except KeyboardInterrupt:
        print("\n[+] Stopped by user (Ctrl+C).")
    finally:
        s2.close()
        s3.close()
        print("[+] Sockets closed. Bye!")


if __name__ == "__main__":
    main()
