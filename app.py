import subprocess
import re
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.offsetbox import OffsetImage, AnnotationBbox
from PIL import Image
import time
from flask import Flask, render_template, request

app = Flask(__name__)

# Set the default image path for all devices
default_image_path = r'static/images/default.png'

# Dictionary to hold MAC address prefixes for vendor identification
vendor_prefixes = {
    'Router': ['00:0C:41', '00:12:17', '00:13:10'],
    'Switch': ['00:1A:2B', '00:1C:BF'],
    'Phone': ['00:1E:58', '00:1A:4D'],
    'PC': ['00:1D:A1', '00:1F:29'],
    'Laptop': ['00:22:15', '00:25:22'],
    'Printer': ['00:1D:7E', '00:1E:58']
}

def nmap_scan(ip_range):
    """Scan the network using Nmap and return the output."""
    command = f"nmap -sn {ip_range}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

def parse_nmap_output(output):
    """Parses the Nmap output and returns a list of devices with their IP addresses, MAC addresses, hostnames, and vendor names."""
    devices = []
    lines = output.split('\n')
    ip_pattern = re.compile(r'\d+\.\d+\.\d+\.\d+')
    mac_pattern = re.compile(r'MAC Address: ([0-9a-fA-F:]+) \((.*?)\)')
    
    for line in lines:
        if "Nmap scan report for" in line:
            ip_address = ip_pattern.search(line)
            if ip_address:
                device = {'ip_address': ip_address.group(0)}
                devices.append(device)
        elif "MAC Address:" in line:
            mac_address = mac_pattern.search(line)
            if mac_address and devices:  # Ensure there's a device to append to
                devices[-1]['mac_address'] = mac_address.group(1)
                devices[-1]['hostname'] = mac_address.group(2)
                devices[-1]['vendor'] = identify_vendor(mac_address.group(1))
    return devices

def identify_vendor(mac_address):
    """Identify the vendor name based on MAC address prefixes."""
    mac_prefix = mac_address[:8]  # Get the first 8 characters (e.g., 00:1A:2B)
    for vendor, prefixes in vendor_prefixes.items():
        if any(mac_prefix.startswith(prefix) for prefix in prefixes):
            return vendor
    return 'Unknown'  # Return 'Unknown' if no vendor matches

def create_network_graph(devices_info, central_node):
    """Creates and visualizes the network graph."""
    G = nx.Graph()
    
    # Add central node
    G.add_node(central_node, device_type='Router')
    
    # Add devices
    for device in devices_info:
        G.add_node(device['ip_address'], device_type='Device', vendor=device.get('vendor', 'Unknown'))
        G.add_edge(central_node, device['ip_address'])
    
    pos = nx.spring_layout(G)
    fig, ax = plt.subplots(figsize=(12, 8))
    add_device_images(G, pos, ax, default_image_path)
    
    # Draw labels
    labels = {node: f"{node}\n{G.nodes[node].get('vendor', 'Unknown')}" for node in G.nodes()}
    nx.draw_networkx_labels(G, pos, labels, font_size=8, font_color='black', font_weight='bold', ax=ax, horizontalalignment='center')
    
    plt.savefig('static/network_diagram.png')  # Save the network diagram to a file
    plt.close(fig)  # Close the figure to free up memory

def add_device_images(G, pos, ax, default_image_path):
    """Adds device images to the network graph."""
    nx.draw(G, pos, with_labels=False, node_size=3000, ax=ax)
    for node in G.nodes():
        (x, y) = pos[node]
        img_path = default_image_path  # Use the default image for all devices
        try:
            image = Image.open(img_path)
            image.thumbnail((50, 50), Image.LANCZOS)
            im = OffsetImage(image, zoom=1)
            ab = AnnotationBbox(im, (x, y), frameon=False)
            ax.add_artist(ab)
        except FileNotFoundError:
            print(f"Warning: Image file '{img_path}' not found.")

def get_network_information():
    """Get network configuration information for the active network."""
    result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
    lines = result.stdout.split('\n')
    active_network_info = []
    for line in lines:
        if "Media State" in line and "Media disconnected" not in line:
            active_network_info.append(line.strip())
        elif "IPv4 Address" in line or "Default Gateway" in line:
            active_network_info.append(line.strip())
    return '\n'.join(active_network_info)

def get_routing_table():
    """Get the IPv4 routing table with active routes."""
    result = subprocess.run(['route', 'print', '-4'], capture_output=True, text=True)
    lines = result.stdout.split('\n')
    active_routes = []
    for line in lines:
        if "===" in line or "Network Destination" in line or "0.0.0.0" in line:
            active_routes.append(line.strip())
    return '\n'.join(active_routes)

@app.route('/', methods=['GET', 'POST'])
def index():
    """Main page to scan the network and display results."""
    if request.method == 'POST':
        ip_range = request.form['ip_range']
        nmap_output = nmap_scan(ip_range)
        devices = parse_nmap_output(nmap_output)

        # Get the default gateway IP address
        gateway_ip = get_default_gateway()
        central_node = gateway_ip if gateway_ip else 'Unknown'

        create_network_graph(devices, central_node)

        # Save all output to a single text file
        with open('network_analysis_output.txt', 'w') as file:
            file.write("Windows IP Configuration (Active Network):\n")
            file.write(get_network_information() + "\n")
            
            file.write("IPv4 Route Table (Active Routes):\n")
            file.write(get_routing_table() + "\n")
            
            file.write("Discovered Devices:\n")
            file.write("{:<20} {:<20} {:<20} {:<20}\n".format("IP Address", "MAC Address", "Hostname", "Vendor"))
            file.write("-" * 80 + "\n")
            for device in devices:
                file.write("{:<20} {:<20} {:<20} {:<20}\n".format(
                    device.get('ip_address', 'N/A'),
                    device.get('mac_address', 'N/A'),
                    device.get('hostname', 'N/A'),
                    device.get('vendor', 'Unknown')
                ))
            
            file.write("\nNmap Output:\n")
            file.write(nmap_output + "\n")

        return render_template('index.html', devices=devices, central_node=central_node, 
                               network_info=get_network_information(), 
                               routing_table=get_routing_table(), 
                               nmap_output=nmap_output)

    return render_template('index.html', devices=None, central_node=None, 
                           network_info=None, routing_table=None, nmap_output=None)

def get_default_gateway():
    """Get the default gateway IP address."""
    result = subprocess.run(['ipconfig'], capture_output=True, text=True)
    lines = result.stdout.split('\n')
    for line in lines:
        if "Default Gateway" in line:
            gateway_ip = line.split(':')[1].strip()
            return gateway_ip
    return None

if __name__ == "__main__":
    app.run(debug=True)