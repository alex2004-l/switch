<br>
Lache Alexandra Florentina Georgiana, 332 CD, 2024-2025

---

## Homework Local Networks - Switch Implementation

---

A basic switch implementation written in __Python__ that supports the following features: __MAC address learning, VLAN communication and minimalistic STP__.

---
__CAM table__:
- the switch adds to its CAM table the source MAC address and incoming port of each received frame
- if the destination MAC address is unknown, the switch floods the frame to all ports except the source port
- in case of _multicast/broadcast_ addresses, the _switch floods all the ports_
- the CAM table is represented by a dictionary that contains the `{MAC address, corresponding port}` associations for efficient lookup

---
__VLAN__:
- the VLAN configuration associated to each port is parsed from the corresponding config file
- the ports are categorized in two different dictionaries depending on their type: `access` or `trunk`
- for each frame received, both tagged and untagged versions are created using the `Frame` class
- when forwarding a frame, the switch sends frames as tagged on trunk ports and untagged on access ports(using a custom version of .1q)

---
__STP__:
- each switch begins by assuming it is the root bridge. After exchanging BPDUs with the other switches, only one is selected as the root bridge(the one with the lowest bridgeID)
- the `BPDU frames` contain the following information: _root bridge ID, sender ID_ and _path cost to the root bridge_. I've used a custom BPDU frame that only contains the relevant information used by the switches from our topology
- after running STP, the trunk ports on each switch can be in one of two states: `BLOCKING` or `LISTENING`. When a frame reaches a blocked port, it isn't forwarded through that port
- if the corresponding port of an entry from the CAM table is blocked, the switch will flood the frame through the other avaiable ports(except the one the frame came from)

---

Challenges and design choices:
- used `struct.pack` and `struct.unpack` for converting numeric data to bytes and vice versa, adjusting arguments based on data type to ensure correct formatting.
- I've used dictionaries in multiple context, for efficient and quick data access(_port type checks, CAM table lookups_)
- created Python classes to mimic C-style structs, allowing structured representation of _port types, frame data, and STP information_, as Python lacks a direct equivalent to C’s struct

---

