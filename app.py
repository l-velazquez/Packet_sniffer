from flask import Flask, render_template
from flask_socketio import SocketIO
import threading
import time
import sniffer 

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'

# CHANGE HERE: Switch to 'threading' so the sniffer doesn't freeze the server
socketio = SocketIO(app, async_mode='threading')

def background_emit():
    while True:
        # Create a package of data to send
        data_to_send = {
            "stats": sniffer.packet_data,
            "packets": list(sniffer.recent_packets) # Send the list of packets
        }
        socketio.emit('update_data', data_to_send)
        time.sleep(1)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    # Start sniffer in a background thread
    sniff_thread = threading.Thread(target=sniffer.start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()

    # Start the data emitter
    socketio.start_background_task(background_emit)

    # Run the server
    socketio.run(app, host='0.0.0.0', port=5000)