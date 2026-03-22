#!/bin/bash
set -e

# Add pox_module to PYTHONPATH so POX can find 'poxpackage'
export PYTHONPATH=$PYTHONPATH:/app:/app/pox_module

# Start OpenVSwitch service
service openvswitch-switch start

# Fix permissions
chmod +x pox/pox.py

# Rebuild router in case it's missing (volume mount overwrite)
echo "Building router..."
cd router && make && cd ..

# 1. Start POX controller
echo "Starting POX..."
export PYTHONPATH=$PYTHONPATH:$(pwd)/pox_module
./pox/pox.py openflow.of_01 pwospf.ofhandler pwospf.srhandler > pox.log 2>&1 &
POX_PID=$!
sleep 5

# Check if POX is still running
if ! kill -0 $POX_PID 2>/dev/null; then
    echo "FATAL: POX controller crashed on startup. Logs:"
    echo "================= pox.log ==================="
    cat pox.log
    echo "============================================="
    exit 1
fi

# 2. Start Mininet Topology (Background first)
# We need to start Mininet, let it initialize enough so we can start the router,
# BUT we also need to interact with it later.
echo "Starting Mininet Topology..."

# Cleanup mininet first just in case
mn -c > /dev/null 2>&1

# We'll run topo.py in the background, but we need to keep its stdin open or connected to the terminal?
# The problem: If we run it in foreground, we can't run step 3.
# If we run it in background, we might lose interactive CLI.
# Solution: Start mininet in background, start router, then wait for mininet.
# HOWEVER, Mininet CLI needs stdin.

# Alternative approach:
# Use a helper script or 'exec' trickery? 
# Or, simply launch the router *inside* a custom mininet script? No, user wants this order.

# The trick: Run the router startup as a separate delayed job, then run mininet in foreground.
(
    echo "Waiting for Mininet to warm up..."
    sleep 10
    echo "Starting SR Routers..."
    ./router/sr -t 300 -s 127.0.0.1 -p 8888 -v vhost1 > sr1.log 2>&1 &
    ./router/sr -t 300 -s 127.0.0.1 -p 8888 -v vhost2 > sr2.log 2>&1 &
    ./router/sr -t 300 -s 127.0.0.1 -p 8888 -v vhost3 > sr3.log 2>&1 &
    # We don't track SR_PID in the main shell this way, but strictly following the requested order:
    # POX -> Topo -> Router
) &

# Run Topo in foreground via Web App
# The Web App (app.py) will spawn 'python2 topo.py' inside a PTY.
echo "Starting Web Interface on port 8060..."

# We use python3 for the Flask app
# The Flask app will be the "foreground" process keeping the container alive.
python3 webapp/app.py

# When user exits Mininet, we cleanup.
echo "Stopping processes..."
kill $POX_PID || true
pkill sr || true
service openvswitch-switch stop
