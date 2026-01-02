#!/usr/bin/env python3
import json, subprocess, os
from datetime import datetime, timezone
from src.forensic_engine import ForensicEngine
from src.honeypot_models import HoneypotNetworkFlow

TSHARK_CMD_TEMPLATE = "tshark -r {pcap} -q -z conv,tcp -z conv,udp -z conv,ip -T json"

def parse_tshark_conv_json(pcap_path):
    # A robust parser would use pyshark or scapy to parse flows; here we call tshark if available
    cmd = ["tshark", "-r", pcap_path, "-T", "json"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return []
    entries = json.loads(proc.stdout)
    # This output is packet-level; for flows use scapy or external tool to aggregate.
    # For brevity, produce a sequence of packets with summary info
    flows = []
    for pkt in entries:
        try:
            layers = pkt.get("_source", {}).get("layers", {})
            ip_layer = layers.get("ip") or layers.get("ipv6", {})
            if not ip_layer:
                continue
            src = ip_layer.get("ip.src") or ip_layer.get("ipv6.src")
            dst = ip_layer.get("ip.dst") or ip_layer.get("ipv6.dst")
            proto = layers.get("frame", {}).get("frame.protocols", "")
            src_port = None; dst_port = None
            if "tcp" in layers:
                tcp = layers["tcp"]
                src_port = tcp.get("tcp.srcport")
                dst_port = tcp.get("tcp.dstport")
            elif "udp" in layers:
                udp = layers["udp"]
                src_port = udp.get("udp.srcport")
                dst_port = udp.get("udp.dstport")
            flows.append({"src": src, "dst": dst, "src_port": src_port, "dst_port": dst_port, "proto": proto})
        except Exception:
            continue
    return flows

def ingest_pcap(pcap_path):
    engine = ForensicEngine()
    db = engine.db
    flows = parse_tshark_conv_json(pcap_path)
    for f in flows:
        nf = HoneypotNetworkFlow(src_ip=f.get("src"), dst_ip=f.get("dst"), src_port=int(f.get("src_port")) if f.get("src_port") else None, dst_port=int(f.get("dst_port")) if f.get("dst_port") else None, proto=f.get("proto"), bytes=None, packets=None)
        db.add(nf)
    db.commit()

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: pcap_ingest.py /path/to/file.pcap")
        sys.exit(1)
    ingest_pcap(sys.argv[1])
