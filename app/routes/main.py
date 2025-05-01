from flask import redirect, url_for, send_from_directory
from app import app

@app.route('/')
def index():
    return redirect(url_for('login'))

