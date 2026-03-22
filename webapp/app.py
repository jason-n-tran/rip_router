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
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')

allowed_origins_env = os.environ.get('ALLOWED_ORIGINS', None)
if allowed_origins_env:
    allowed_origins = allowed_origins_env.split(',')
    print(f"CORS: Restricting to specific origins: {allowed_origins}")
else:
    allowed_origins = "*"
    print("CORS: Allowing all origins (development mode)")

socketio = SocketIO(app, cors_allowed_origins=allowed_origins, async_mode='eventlet')

fd_master = None
proc = None
output_buffer = []

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
        (master, slave) = pty.openpty()
        fd_master = master
        
        cmd = "python2 -u demo.py"
        
        proc = subprocess.Popen(
            shlex.split(cmd),
            stdin=slave,
            stdout=slave,
            stderr=slave,
            cwd="/app",
            close_fds=True
        )
        print(f"Started process {proc.pid}")
        
        socketio.start_background_task(target=read_and_forward_pty_output, fd=fd_master, socket_io_instance=socketio)

@socketio.on('connect')
def handle_connect():
    print("Client connected attached to existing session")
    global output_buffer
    if output_buffer:
        emit('term_output', {'output': "".join(output_buffer)})

def read_and_forward_pty_output(fd, socket_io_instance):
    """Reads output from the PTY master and emits it to the websocket."""
    global output_buffer
    max_read_bytes = 1024 * 20
    print("Reading thread started")
    while True:
        socket_io_instance.sleep(0.01)
        if fd:
            try:
                (r, w, x) = select.select([fd], [], [], 0.1)
                if fd in r:
                    output = os.read(fd, max_read_bytes).decode(errors='ignore')
                    if output:
                        output_buffer.append(output)
                        if len(output_buffer) > 1000:
                             output_buffer = output_buffer[-1000:]
                        
                        socket_io_instance.emit('term_output', {'output': output})
            except OSError as e:
                print(f"OSError reading PTY: {e}")
                break



@socketio.on('term_input')
def handle_term_input(data):
    global fd_master
    if fd_master:
        user_input = data.get('input', '')
        if len(user_input) > 1024:
            print(f"SECURITY: Input too large: {len(user_input)} bytes")
            return
        
        if user_input.strip():
            print(f"AUDIT: User input: {repr(user_input[:100])}")  # Log first 100 chars
        
        os.write(fd_master, user_input.encode())

@socketio.on('resize')
def handle_resize(data):
    if fd_master:
        rows = min(int(data.get('rows', 24)), 200)
        cols = min(int(data.get('cols', 80)), 200)
        set_winsize(fd_master, rows, cols)

if __name__ == '__main__':
    start_mininet()
    socketio.run(app, host='0.0.0.0', port=8060, allow_unsafe_werkzeug=True)
