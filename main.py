import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'vps_manager'))

from vps_manager.app import app, db, socketio

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
