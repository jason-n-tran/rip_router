import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import pty
import os
import subprocess
import select
import termios
import struct
import fcntl
import shlex
import sys
import threading
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Store the file descriptor for the master end of the pseudo-terminal
fd_master = None
proc = None
output_buffer = [] # Store output history

def set_winsize(fd, row, col, xpix=0, ypix=0):
    winsize = struct.pack("HHHH", row, col, xpix, ypix)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)

@app.route('/')
def index():
    return render_template('index.html')

def start_mininet():
    global fd_master, proc
    if fd_master is None:
        print("Spawning Mininet CLI immediately...")
        # Create a pseudo-terminal pair
        (master, slave) = pty.openpty()
        fd_master = master
        
        # Start the Mininet CLI process
        # We use python2 explicitly as required by Mininet
        # Use -u for unbuffered output to ensure we see it immediately
        cmd = "python2 -u demo.py"
        
        # Spawn the process
        proc = subprocess.Popen(
            shlex.split(cmd),
            stdin=slave,
            stdout=slave,
            stderr=slave,
            cwd="/app", # Ensure CWD is correct for topo.py
            close_fds=True
        )
        print(f"Started process {proc.pid}")
        
        # Start a background task managed by SocketIO/Eventlet
        socketio.start_background_task(target=read_and_forward_pty_output, fd=fd_master, socket_io_instance=socketio)

@socketio.on('connect')
def handle_connect():
    # When a client connects, they just attach to the existing stream via the global fd_master
    print("Client connected attached to existing session")
    # Emit buffered history so the user sees what happened
    global output_buffer
    if output_buffer:
        emit('term_output', {'output': "".join(output_buffer)})

def read_and_forward_pty_output(fd, socket_io_instance):
    """Reads output from the PTY master and emits it to the websocket."""
    global output_buffer
    max_read_bytes = 1024 * 20
    print("Reading thread started")
    while True:
        socket_io_instance.sleep(0.01) # Yield to eventlet loop
        if fd:
            try:
                # Use os.read which is blocking, but with eventlet it should be fine if patched
                # However, for safety in PTY reading with select to avoid blocking forever if no data
                (r, w, x) = select.select([fd], [], [], 0.1)
                if fd in r:
                    output = os.read(fd, max_read_bytes).decode(errors='ignore')
                    if output:
                        # Append to buffer (limit size if needed, e.g., last 100KB)
                        output_buffer.append(output)
                        if len(output_buffer) > 1000: # Simple cleanup to prevent unbounded growth
                             output_buffer = output_buffer[-1000:]
                        
                        socket_io_instance.emit('term_output', {'output': output})
            except OSError as e:
                print(f"OSError reading PTY: {e}")
                break


@socketio.on('term_input')
def handle_term_input(data):
    global fd_master
    if fd_master:
        os.write(fd_master, data['input'].encode())

@socketio.on('resize')
def handle_resize(data):
    if fd_master:
        set_winsize(fd_master, data['rows'], data['cols'])

if __name__ == '__main__':
    # Start Mininet before the web server starts accepting connections
    start_mininet()
    # We use eventlet/gevent for production usually, but for dev this is fine.
    # Host 0.0.0.0 is crucial for Docker.
    socketio.run(app, host='0.0.0.0', port=8080, allow_unsafe_werkzeug=True)
