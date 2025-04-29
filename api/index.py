from flask import Flask, request
import sys
import os

# Ana klasörü sys.path'e ekle
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Ana uygulama modülünü import et
from app import app as flask_app

# Vercel için export
app = flask_app 