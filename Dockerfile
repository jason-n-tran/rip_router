FROM ubuntu:20.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and install system dependencies
# mininet, openvswitch-switch, python2, net-tools, build-essential, python-setuptools
# + utils: ping, traceroute, wget, curl, iproute2
# Install system dependencies including Python 3 for the webapp
RUN apt-get update && apt-get install -y \
    mininet \
    openvswitch-switch \
    python2 \
    net-tools \
    iputils-ping \
    iputils-arping \
    traceroute \
    wget \
    curl \
    build-essential \
    python-setuptools \
    iproute2 \
    python3 \
    python3-pip \
    dos2unix \
    && rm -rf /var/lib/apt/lists/*


# Install Python 2 dependencies (for Mininet/POX)
RUN curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py && \
    python2 get-pip.py && \
    rm get-pip.py

RUN pip2 install ltprotocol "Twisted==20.3.0"

# Install Python 3 dependencies (for WebApp)
RUN pip3 install flask flask-socketio eventlet gunicorn gevent gevent-websocket

WORKDIR /app

# Copy the entire project
COPY . /app

# Build the router (requires make and gcc, installed via build-essential)
RUN cd router && make

# Expose Web Port
EXPOSE 8080

RUN dos2unix entrypoint.sh grader.py
RUN chmod +x entrypoint.sh grader.py

# Use entrypoint script to start services
ENTRYPOINT ["./entrypoint.sh"]
