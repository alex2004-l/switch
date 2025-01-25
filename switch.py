#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name


# A class used for retaining the types of ports connected to the switch
class Ports:
    def __init__(self):
        self.access_ports = {}
        self.trunk_ports = {}


# A class for switch STP data
class Switch:
    def __init__(self, priority):
        self.mac_addr = get_switch_mac()
        self.priority = priority

        self.root_bridge_ID = priority
        self.root_path_cost = 0
        self.root_port = 0
        

# A class for retaining both the tagged and untagged version of a frame
class Frame:
    def __init__(self, vlan_id, data, new_tag=0):
        if vlan_id == -1:
            self.tagged = data[0:12] + create_vlan_tag(new_tag) + data[12:]
            self.untagged = data
        else:
            self.tagged = data
            self.untagged = data[0:12] + data[16:]


# Function for parsing the ethernet header of a frame
def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

# Parsing the switch port configuration from its .cfg file
def parse_config(id, interfaces_names):
    file = open("configs/switch{}.cfg".format(id), 'r')
    lines = file.readlines()

    priority = int(lines[0].rstrip())
    ports = Ports()

    for line in lines[1:]:
        interface_name, vlan_id = line.split()
        if vlan_id == "T":
            # All the trunk ports are initially set as BLOCKED
            ports.trunk_ports[interfaces_names[interface_name]] = "BLOCKED"
        else:
            ports.access_ports[interfaces_names[interface_name]] = int(vlan_id)

    return priority, ports

# Initializing STP bridge
def initialize_bridge(switch, trunk_ports):
    # Changing the status of all trunk ports to LISTENING
    if switch.root_bridge_ID == switch.priority:
        for port in trunk_ports:
            trunk_ports[port] = "LISTENING"

# Creates a vlan tag that needs to be added to a bytes frame
def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

# Method that creates a bpdu frame base on the switch STP info
def create_bpdu(switch):
    destination_mac = bytes.fromhex("01:80:c2:00:00:00".replace(":", ""))
    llc_length = struct.pack("!H", 0x0017)
    llc_header = struct.pack("!B", 0x42) + struct.pack("!B", 0x42) + struct.pack("!B", 0x03)
    bpdu_config = struct.pack("!QIQ", switch.root_bridge_ID, switch.root_path_cost, switch.priority)

    bpdu_message = destination_mac + switch.mac_addr + llc_length + llc_header + bpdu_config
    return bpdu_message

# Function through the root bridge sends BPDU packets to all the other switches
def send_bdpu_every_sec(switch, trunk_ports):
    while True:
        if switch.priority == switch.root_bridge_ID:
            bpdu_message = create_bpdu(switch)
            for port in trunk_ports:
                send_to_link(port, len(bpdu_message), bpdu_message)
        time.sleep(1)

# Unpacking the BPDU message and updating the STP infos
def receive_bpdu(switch, data, port, trunk_ports):
    bpdu_root_bridge, bpdu_root_path_cost, bpdu_bridge_id = struct.unpack("!QIQ", data[17:])

    if bpdu_root_bridge < switch.root_bridge_ID:
        switch.root_path_cost += bpdu_root_path_cost + 10
        switch.root_port = port

        if switch.root_bridge_ID == switch.priority:
            for p in trunk_ports:
                trunk_ports[p] = "BLOCKED"
        
        trunk_ports[switch.root_port] = "LISTENING"
        switch.root_bridge_ID = bpdu_root_bridge

        new_bpdu = create_bpdu(switch)

        for p in trunk_ports:
            if p != switch.root_port:
                send_to_link(p, len(new_bpdu), new_bpdu)
    
    elif bpdu_root_bridge == switch.root_bridge_ID:
        if port == switch.root_port & bpdu_root_path_cost + 10 < switch.root_path_cost:
            switch.root_path_cost = bpdu_root_path_cost + 10
        elif port != switch.root_port:
            if bpdu_root_path_cost > switch.root_path_cost:
                trunk_ports[port] = "LISTENING"
    elif bpdu_bridge_id == switch.priority:
        trunk_ports[port] = "BLOCKED"
    
    if switch.priority == switch.root_bridge_ID:
        for port in trunk_ports:
            trunk_ports[port] = "LISTENING"

# Checking wheter a mac address is unicast
def is_unicast(mac_addr):
    first_byte = int(mac_addr.split(":")[0], 16)
    return (first_byte & 0b1) == 0

# Flooding a frame on all switch ports except the one it came
def flood_frame(interface, interfaces, frame, ports, vlan_id):
    for port in interfaces:
        if port != interface:
            if port in ports.trunk_ports:
                if ports.trunk_ports[port] != "BLOCKED":
                    send_to_link(port, len(frame.tagged), frame.tagged)
            else:
                if vlan_id == -1 and ports.access_ports[interface] == ports.access_ports[port]:
                    send_to_link(port, len(frame.untagged), frame.untagged)
                elif vlan_id == ports.access_ports[port]:
                    send_to_link(port, len(frame.untagged), frame.untagged)


def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)
    interfaces_names = {}
    cam_table = {}

    # Create and start a new thread that deals with sending BDPU

    # Printing interface names
    for i in interfaces:
        interfaces_names[get_interface_name(i)] = i

    priority, ports = parse_config(switch_id, interfaces_names)

    switch = Switch(priority)
    initialize_bridge(switch, ports.trunk_ports)

    t = threading.Thread(target=send_bdpu_every_sec, args=(switch, ports.trunk_ports))
    t.start()

    while True:
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        if dest_mac == "01:80:c2:00:00:00":
            receive_bpdu(switch, data, interface, ports.trunk_ports)
            continue

        # Creating for a frame both the tagged/untagged version
        try:
            # If the frame comes from an trunk port, this line will fail
            frame = Frame(vlan_id, data, ports.access_ports[interface])
        except:
            # and this one will be executed
            frame = Frame(vlan_id, data)

        # Adding the source mac to the CAM table
        cam_table[src_mac] = interface
        
        if is_unicast(dest_mac):
            if dest_mac in cam_table:
                if cam_table[dest_mac] in ports.trunk_ports:
                    # If after a STP update the corresponding port for an entry becomes blocked
                    # flood all the other interfaces
                    if ports.trunk_ports[cam_table[dest_mac]] != "BLOCKED":
                        send_to_link(cam_table[dest_mac], len(frame.tagged), frame.tagged)
                    else:
                        flood_frame(interface, interfaces, frame, ports, vlan_id)
                else:
                    if vlan_id == -1 and ports.access_ports[interface] == ports.access_ports[cam_table[dest_mac]]:
                        send_to_link(cam_table[dest_mac], len(frame.untagged), frame.untagged)
                    elif vlan_id == ports.access_ports[cam_table[dest_mac]]:
                        send_to_link(cam_table[dest_mac], len(frame.untagged), frame.untagged)
            else:
                flood_frame(interface, interfaces, frame, ports, vlan_id)
        else:
            flood_frame(interface, interfaces, frame, ports, vlan_id)


if __name__ == "__main__":
    main()
