import zlib
import json

with open('./shared/config.json', 'r') as file:
    data = json.load(file)

# Convert JSON to string and encode to bytes
json_data = json.dumps(data).encode('utf-8')

# Compress the data using zlib
compressed_data = zlib.compress(json_data)

# Write the binary compressed data to a file
with open('./shared/config.bin', 'wb') as f:
    f.write(compressed_data)

print(f'Compressed file written as config.bin')
