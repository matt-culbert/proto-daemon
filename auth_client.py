import requests
import hmac
import hashlib
import time

secret_key = "4321"


def generate_auth_token(client_uri):
    # Generate a timestamp (e.g., current Unix time)
    client_timestamp = str(int(time.time()))

    # Create an HMAC using the URI and timestamp
    message = f"{client_uri}:{client_timestamp}"
    hmac_obj = hmac.new(secret_key.encode(), message.encode(), hashlib.sha256)
    client_token = hmac_obj.hexdigest()

    return client_token, client_timestamp


# Generate the token and timestamp for the URI
uri = "1234"
token, timestamp = generate_auth_token(uri)

# Make a GET request to the Flask server with token and timestamp
response = requests.get(f"http://localhost:5000/auth/{uri}", params={"token": token, "timestamp": timestamp})

print(response.json())
