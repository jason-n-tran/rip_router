# POX Controller

A networking controller implementation for managing OpenFlow switches and network topology.

## Overview

This project contains the POX controller framework, which provides tools for developing network control applications and managing software-defined networks (SDN).

## Directory Structure

- **pox/** - Main controller implementation
  - **controllers/** - Controller implementations
  - **forwarding/** - Forwarding logic and learning switch implementations
  - **openflow/** - OpenFlow protocol implementation
  - **lib/** - Utility libraries and helper modules
  - **topology/** - Network topology management
  - **web/** - Web interface components

- **tests/** - Unit tests and test utilities
- **tools/** - Utility scripts and tools
- **doc/** - Documentation

## Getting Started

1. Ensure Python is installed on your system
2. Run POX controller using:
   ```
   python pox.py [module_name]
   ```

## Key Features

- OpenFlow switch control and management
- Network topology discovery
- L2/L3 learning switches
- Distributed controller support
- GUI backend for monitoring

## Documentation

See the `doc/` directory for additional documentation and configuration templates.
