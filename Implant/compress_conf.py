import zlib
import json

"""
The makefile uses this to determine if listeners are expecting compression
If the listener wants compression, then the config is compressed and written as a bin file
This is then embedded at compile time
The script outputs 'withComp' to the terminal and this tells the makefile to use the 'withComp' tag
Otherwise, no compression is used and the config is written as a json file and embedded raw
If you don't use compression, this config is very simple to extract from the exe
"""

with open('../Server/s_conf.json', 'r') as file:
    data = json.load(file)

psk1 = data["keys"][0]["psk1"]
psk2 = data["keys"][0]["psk2"]
host = data["host_info"][0]["host"]
method = data["host_info"][0]["method"]
port = data["host_info"][0]["port"]
get_path = data["default-GET"][0]["path"]
post_path = data["default-POST"][0]["path"]
is_compression = data["default-GET"][0]["comp"].lower() == "true"

config = {
    "psk1": psk1,
    "psk2": psk2,
    "host": host,
    "method": method,
    "port": port,
    "get_path": get_path,
    "post_path": post_path
}

if is_compression:
    # Convert JSON to string and encode to bytes
    json_data = json.dumps(config).encode('utf-8')

    # Compress the data using zlib
    compressed_data = zlib.compress(json_data)

    # Write the binary compressed data to a file
    with open('./shared/config.bin', 'wb') as f:
        f.write(compressed_data)

    print('withComp')

else:
    json_data = json.dumps(config)

    # Write the JSON data to file
    with open('./shared/config.json', 'w') as f:
        f.write(json_data)

    print("noComp")
