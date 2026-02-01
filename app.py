"""
Flask + SocketIO Web Server for Packet Sniffer
"""

import threading
import time

from flask import Flask, render_template
from flask_socketio import SocketIO

from sniffer import PacketSniffer

app = Flask(__name__)
app.config["SECRET_KEY"] = "packet-sniffer-secret"

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# Initialize sniffer
sniffer = PacketSniffer(max_history=200)


def packet_callback(packet_info):
    """Called when a new packet is captured."""
    socketio.emit("new_packet", packet_info)


sniffer.on_packet = packet_callback


def stats_emitter():
    """Emit stats periodically."""
    while True:
        time.sleep(1)
        stats = sniffer.get_stats()
        socketio.emit("stats_update", stats)


@app.route("/")
def index():
    return render_template("index.html")


@socketio.on("connect")
def handle_connect():
    print("Client connected")
    # Send current stats and history on connect
    socketio.emit("stats_update", sniffer.get_stats())
    socketio.emit("history", sniffer.get_history())


@socketio.on("disconnect")
def handle_disconnect():
    print("Client disconnected")


def start_sniffer():
    """Start the packet sniffer in a separate thread."""
    sniffer_thread = threading.Thread(target=sniffer.start, daemon=True)
    sniffer_thread.start()


if __name__ == "__main__":
    print("Starting Packet Sniffer Web Dashboard...")
    print("NOTE: Run with sudo for packet capture permissions")
    print("Open http://localhost:5000 in your browser")

    # Start background threads
    start_sniffer()
    stats_thread = threading.Thread(target=stats_emitter, daemon=True)
    stats_thread.start()

    # Run the web server
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
