# RIP Router Implementation

A comprehensive implementation of a Routing Information Protocol (RIP) router with integrated OpenFlow switch control and Software-Defined Networking (SDN) capabilities.

## Overview

This project implements a fully functional RIP router that combines classical distance-vector routing protocols with modern SDN technologies. The implementation consists of three core components:

1. **C-based Router Core** (`router/`) - A lightweight, high-performance router implementation supporting RIP routing, ARP resolution, ICMP messaging, and packet forwarding
2. **POX Controller Framework** (`pox/`) - A comprehensive network control platform providing OpenFlow switch management, topology discovery, and network monitoring
3. **PWOSPF Module** (`pox_module/pwospf/`) - A bridge layer integrating the RIP router with OpenFlow switches through the VNS (Virtual Network System) protocol

## Architecture

### Component Overview

The router architecture follows a modular design with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────┐
│              POX Controller Framework                    │
│  (OpenFlow Protocol, Network Management, Control Logic) │
└──────────────────┬──────────────────────────────────────┘
                   │
        ┌──────────┴──────────┐
        │                     │
   ┌────▼──────┐      ┌───────▼──────┐
   │ OpenFlow  │      │ PWOSPF Module│
   │ Handler   │      │  (VNS Bridge)│
   └────┬──────┘      └───────┬──────┘
        │                     │
        └──────────┬──────────┘
                   │
        ┌──────────▼──────────┐
        │   RIP Router Core   │
        │  (C Implementation) │
        └─────────────────────┘
```

### Core Functionality

#### Router Core (C Implementation)

The router implementation (`router/sr_*.c`) provides:

- **Packet Processing**: IPv4 packet forwarding with TTL decrement and validation
- **Routing**: Distance-vector RIP routing with dynamic routing table updates
- **ARP Protocol**: ARP request/reply handling and ARP cache management with timeout mechanisms
- **ICMP Protocol**: ICMP echo (ping) support and error message generation (destination unreachable, time exceeded)
- **Interface Management**: Multi-interface support with MAC address and IP address binding
- **Network Communication**: VNS protocol integration for virtual network connectivity

Key files:
- `sr_router.c/h` - Main packet handling and routing logic
- `sr_main.c` - Router initialization and command-line interface
- `sr_rt.c/h` - Routing table management
- `sr_arpcache.c/h` - ARP cache with timeout-based invalidation
- `sr_if.c/h` - Interface configuration and management
- `sr_vns_comm.c` - VNS protocol communication
- `sr_protocol.h` - Network protocol definitions and packet structures

#### POX Controller Framework

The POX framework provides a robust foundation for SDN applications:

- **OpenFlow Protocol Support**: Full OpenFlow 1.0 implementation with extensible protocol handling
- **Event-Driven Architecture**: Reactive event handling for network events and controller actions
- **Network Discovery**: Automatic topology discovery and link-state monitoring
- **Packet Processing**: Raw packet capture and manipulation at the switch level
- **Scalability**: Support for multiple switch controllers and distributed deployments

Key components:
- `pox/openflow/` - OpenFlow 1.0 protocol implementation
- `pox/lib/packet/` - Network packet parsing and construction (Ethernet, IPv4, ARP, ICMP, UDP, DNS)
- `pox/lib/addresses.py` - IP and MAC address handling utilities
- `pox/lib/util.py` - General utility functions
- `pox/forwarding/` - L2/L3 forwarding implementations

#### PWOSPF Module (VNS Bridge)

The PWOSPF module bridges the router and OpenFlow controller:

- **VNS Protocol Handler** (`VNSProtocol.py`): Implements the Virtual Network System protocol for communication between the router and virtual network infrastructure
- **OpenFlow Handler** (`ofhandler.py`): Manages OpenFlow switch connections and packet exchange
- **SR Handler** (`srhandler.py`): Handles Simple Router (SR) packet operations and routing updates

## Directory Structure

```
.
├── router/                          # C-based router implementation
│   ├── sr_router.c/h               # Core routing and packet forwarding
│   ├── sr_main.c                   # Router initialization
│   ├── sr_rt.c/h                   # Routing table management
│   ├── sr_arpcache.c/h             # ARP cache implementation
│   ├── sr_if.c/h                   # Interface management
│   ├── sr_vns_comm.c               # VNS protocol communication
│   ├── sr_protocol.h               # Protocol definitions
│   ├── sr_utils.c/h                # Utility functions
│   ├── sr_dumper.c/h               # Packet dumping/debugging
│   ├── sha1.c/h                    # SHA-1 hashing for authentication
│   ├── vnscommand.h                # VNS command definitions
│   └── Makefile                    # Build configuration
│
├── pox/                             # POX controller framework
│   ├── pox/
│   │   ├── core.py                 # Core controller framework
│   │   ├── boot.py                 # Bootstrap and initialization
│   │   ├── openflow/               # OpenFlow protocol implementation
│   │   │   ├── libopenflow_01.py   # OpenFlow 1.0 library
│   │   │   ├── of_service.py       # OpenFlow service layer
│   │   │   └── ...
│   │   ├── lib/                    # Utility libraries
│   │   │   ├── packet/             # Packet parsing/construction
│   │   │   ├── addresses.py        # Address handling
│   │   │   ├── revent/             # Event framework
│   │   │   ├── recoco/             # Cooperative multitasking
│   │   │   └── ...
│   │   ├── forwarding/             # Forwarding implementations
│   │   ├── topology/               # Topology management
│   │   └── misc/                   # Miscellaneous utilities
│   ├── tests/                      # Unit tests
│   └── pox.py                      # Main entry point
│
├── pox_module/                      # RIP/PWOSPF integration module
│   ├── setup.py                    # Python package configuration
│   └── pwospf/
│       ├── __init__.py
│       ├── ofhandler.py            # OpenFlow switch handler
│       ├── srhandler.py            # Simple Router packet handler
│       └── VNSProtocol.py          # VNS protocol implementation
│
├── http_server1/                    # Test HTTP server 1
│   ├── webserver.py
│   └── index.html
│
├── http_server2/                    # Test HTTP server 2
│   ├── webserver.py
│   └── index.html
│
├── rtable.vhost1                    # Routing table for virtual host 1
├── rtable.vhost2                    # Routing table for virtual host 2
├── rtable.vhost3                    # Routing table for virtual host 3
├── topo.py                          # Mininet topology definition
├── IP_CONFIG                        # IP configuration file
├── auth_key                         # Authentication credentials
└── README.md                        # This file
```

## Building and Running

### Prerequisites

- **Linux environment** (x86_64 architecture recommended)
- **C compiler** (gcc)
- **Python** 2.7+ or 3.x
- **Mininet** (for network topology simulation)
- **Make** (for C compilation)

### Building the Router

```bash
cd router
make
```

This generates the `sr` executable binary for the router.

### Running the Router

```bash
./router/sr -t <topology_id> -v <virtual_host_id> -s <server_hostname> -u <username> -p <port>
```

**Command-line Options:**
- `-t <topo_id>` - Topology ID (integer)
- `-v <vhost>` - Virtual host identifier (e.g., vhost1, vhost2)
- `-s <server>` - Server hostname for VNS connection
- `-u <username>` - Username for authentication
- `-p <port>` - Server port (default: 8888)
- `-r <rtable>` - Routing table configuration file
- `-h` - Display usage information

Example:
```bash
./router/sr -t 0 -v vhost1 -s localhost -u testuser -p 8888 -r rtable.vhost1
```

### Running the POX Controller

```bash
python pox.py <module_name>
```

**Common modules:**
- `forwarding.hub` - L2 hub functionality
- `forwarding.l2_learning` - L2 learning switch
- `pwospf.ofhandler` - PWOSPF OpenFlow handler

Example:
```bash
python pox.py pwospf.ofhandler
```

### Running the Mininet Topology

```bash
python topo.py
```

This launches the network topology defined in `topo.py`, creating virtual switches and hosts for testing.

## Configuration Files

### Routing Table Format

Routing tables are text files defining static routes. Format:
```
<destination_ip> <gateway_ip> <subnet_mask> <interface_name>
```

Example (`rtable.vhost1`):
```
10.0.0.0 10.3.0.1 255.0.0.0 eth0
10.1.0.0 10.3.0.2 255.0.0.0 eth1
```

### IP Configuration

The `IP_CONFIG` file specifies IP addresses and interfaces for virtual hosts:
```
<vhost_id> <interface_name> <ip_address> <subnet_mask> <mac_address>
```

## Key Features

### RIP Router Capabilities

- **Distance-Vector Routing**: Dynamic routing using RIP protocol
- **Multi-Interface Support**: Configuration for multiple network interfaces per router
- **Packet Forwarding**: Efficient IPv4 packet forwarding with longest-prefix matching
- **ARP Resolution**: Automatic MAC address resolution with caching
- **ICMP Support**: Echo request/reply and error messages
- **TTL Management**: TTL decrement and validation on forwarded packets
- **Error Handling**: Proper error reporting for unreachable destinations and exceeded TTLs

### OpenFlow Integration

- **Switch Control**: Direct OpenFlow 1.0 switch management
- **Flow Table Management**: Flow insertion and removal capabilities
- **Packet Inspection**: Raw packet access for advanced routing decisions
- **Port Management**: Per-interface traffic control
- **Statistics**: Collection of switch performance metrics

### Network Testing

- **Topology Simulation**: Virtual topology with Mininet
- **HTTP Test Servers**: Built-in HTTP servers for connectivity testing
- **Packet Dumping**: Raw packet capture and analysis capabilities
- **Debug Logging**: Comprehensive logging for troubleshooting

## RIP Protocol Details

The Routing Information Protocol (RIP) is a classical distance-vector routing protocol with the following characteristics:

- **Metric**: Hop count (maximum 15, with 16 representing infinity/unreachable)
- **Update Mechanism**: Periodic routing table updates via UDP port 520
- **Convergence**: Slow convergence (up to several minutes in large networks)
- **Maximum Hops**: Limited to 15 hops
- **Split Horizon**: Optional mechanism to prevent routing loops

This implementation supports RIPv1/RIPv2 packet formats and standard distance-vector algorithms.

## Development and Testing

### Unit Tests

Unit tests are located in `pox/tests/` and can be executed with:
```bash
python -m pytest pox/tests/
```

### Packet Dumping

Enable packet dumping to analyze network traffic:
```python
# In router code
sr_dumper.c provides packet dump functionality
```

### Debug Mode

Compile with debug symbols for detailed logging:
```bash
cd router
make clean
# Modify Makefile to add -g flag
make
```

## Performance Considerations

- **Scalability**: Supports networks with hundreds of routers
- **Convergence Time**: RIP convergence time scales with network diameter
- **Memory Usage**: Minimal memory footprint suitable for embedded systems
- **CPU Overhead**: Low CPU usage during normal operation

## Security Considerations

- **Authentication**: VNS protocol supports SHA-1 based authentication (see `sha1.c`)
- **Access Control**: User authentication via credentials file
- **ARP Spoofing**: Standard ARP validation implemented
- **Input Validation**: Packet validation and malformed packet handling

## Protocol Standards

This implementation follows these networking standards:

- **RFC 1058** - Routing Information Protocol (RIPv1)
- **RFC 2453** - RIP Version 2 (RIPv2)
- **RFC 791** - Internet Protocol (IPv4)
- **RFC 792** - Internet Control Message Protocol (ICMP)
- **RFC 826** - Address Resolution Protocol (ARP)
- **RFC 3610** - OpenFlow 1.0 Protocol Specification

## Troubleshooting

### Router Won't Start

1. Verify VNS server is running and accessible
2. Check authentication credentials in `auth_key`
3. Ensure routing table files exist and are readable
4. Review logs in the router output

### Packets Not Forwarding

1. Verify routing table entries are correct
2. Check ARP cache for MAC address resolution
3. Ensure interfaces are properly configured
4. Use packet dumping to diagnose packet flow

### OpenFlow Switch Issues

1. Verify POX controller is running
2. Check OpenFlow handshake in debug logs
3. Ensure network connectivity between switches and controller
4. Validate flow table entries

## Contributing

When contributing to this project:

1. Follow existing code style and conventions
2. Include appropriate error handling
3. Add unit tests for new functionality
4. Document API changes and additions
5. Test across all supported virtual hosts

## License

This project incorporates code from the POX controller framework (GPLv3) and components developed for educational networking research.

## References

- POX Controller: https://github.com/noxrepo/pox
- Mininet: http://mininet.org/
- OpenFlow Specification: https://opennetworking.org/
- RFC Series: https://tools.ietf.org/html/

## Authors and Contributors

This implementation combines:
- POX controller framework by James McCauley and contributors
- VNS protocol implementation
- RIP router implementation for educational and research purposes
