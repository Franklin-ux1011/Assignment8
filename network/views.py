from django.shortcuts import render

# Create your views here.

from django.shortcuts import render, redirect
from .forms import DhcpRequestForm
from datetime import datetime, timedelta
from pymongo import MongoClient
import re

# in-memory leases so same MAC gets same IP
LEASES = {}

# IPv4 pool start (we'll just count up)
IPV4_NETWORK = "192.168.1."
IPV4_START = 10  # start from .10 to avoid gateway
LEASE_TIME_SECONDS = 3600


MONGO_HOST = "172.31.6.58"
MONGO_PORT = 27017
MONGO_DB = "dhcpdb"
MONGO_COL = "leases"

def get_mongo_collection():
    client = MongoClient(f"mongodb://{MONGO_HOST}:{MONGO_PORT}/")
    db = client[MONGO_DB]
    return db[MONGO_COL]

def valid_mac(mac):
    pattern = r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$"
    return re.match(pattern, mac) is not None

def assign_ipv4(mac):
    if mac in LEASES and LEASES[mac]['dhcp_version'] == 'DHCPv4':
        return LEASES[mac]['assigned_ip']

    used_ips = {v['assigned_ip'] for v in LEASES.values() if v['dhcp_version'] == 'DHCPv4'}
    for host in range(IPV4_START, 255):
        candidate = f"{IPV4_NETWORK}{host}"
        if candidate not in used_ips:
            return candidate
    return None  # pool exhausted

def mac_to_eui64_ipv6(mac):
    # mac like "00:1A:2B:3C:4D:5E"
    parts = mac.split(":")
    mac_bytes = [int(p, 16) for p in parts]

    mac_bytes[0] = mac_bytes[0] ^ 0x02  # toggle U/L bit

    eui64 = mac_bytes[0:3] + [0xFF, 0xFE] + mac_bytes[3:]

    # format to IPv6 under 2001:db8::/64
    # eui64 is 8 bytes -> 4 groups of 16 bits
    groups = [
        (eui64[0] << 8) + eui64[1],
        (eui64[2] << 8) + eui64[3],
        (eui64[4] << 8) + eui64[5],
        (eui64[6] << 8) + eui64[7],
    ]
    # base prefix
    ipv6 = f"2001:db8::{groups[0]:04x}:{groups[1]:04x}:{groups[2]:04x}:{groups[3]:04x}"
    return ipv6

def dhcp_request_view(request):
    if request.method == 'POST':
        form = DhcpRequestForm(request.POST)
        if form.is_valid():
            mac = form.cleaned_data['mac_address']
            version = form.cleaned_data['dhcp_version']

            if not valid_mac(mac):
                return render(request, 'network/form.html', {
                    'form': form,
                    'error': 'Invalid MAC format'
                })

            if version == 'DHCPv4':
                assigned_ip = assign_ipv4(mac)
            else:
                assigned_ip = mac_to_eui64_ipv6(mac)

            lease_end = datetime.utcnow() + timedelta(seconds=LEASE_TIME_SECONDS)

            # save in memory
            LEASES[mac] = {
                'mac_address': mac,
                'dhcp_version': version,
                'assigned_ip': assigned_ip,
                'lease_time': LEASE_TIME_SECONDS,
                'timestamp': datetime.utcnow(),
            }

            # save in Mongo
            col = get_mongo_collection()
            col.insert_one({
                "mac_address": mac,
                "dhcp_version": version,
                "assigned_ip": assigned_ip,
                "lease_time": f"{LEASE_TIME_SECONDS} seconds",
                "timestamp": datetime.utcnow().isoformat()
            })

            return render(request, 'network/result.html', {
                'mac': mac,
                'dhcp_version': version,
                'assigned_ip': assigned_ip,
                'lease_time': LEASE_TIME_SECONDS,
            })
    else:
        form = DhcpRequestForm()

    return render(request, 'network/form.html', {'form': form})

def view_leases(request):
    col = get_mongo_collection()
    all_leases = list(col.find().sort("timestamp", -1))
    return render(request, 'network/leases.html', {'leases': all_leases})
