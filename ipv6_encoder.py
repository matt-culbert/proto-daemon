import ipaddress


def string_to_ipv6(data: str) -> list:
    """
    Encode a string into a list of IPv6 addresses.

    Parameters:
        data (str): The input string to encode.

    Returns:
        list: A list of IPv6 addresses representing the encoded data.
    """
    # Convert string to its hexadecimal representation
    hex_data = data.encode('utf-8').hex()

    # Pad with '0' to make it a multiple of 32 hex digits (16 bytes per IPv6 address)
    padding_length = (32 - len(hex_data) % 32) % 32
    hex_data += '0' * padding_length

    # Split into chunks of 32 hex digits (16 bytes each)
    chunks = [hex_data[i:i + 32] for i in range(0, len(hex_data), 32)]

    # Convert each chunk into an IPv6 address
    encoded_ipv6_addresses = [str(ipaddress.IPv6Address(int(chunk, 16))) for chunk in chunks]

    return encoded_ipv6_addresses


def ipv6_to_string(ipv6_encoded_addresses: list) -> str:
    """
    Decode a list of IPv6 addresses back into the original string.

    Parameters:
        ipv6_encoded_addresses (list): A list of IPv6 addresses.

    Returns:
        str: The decoded original string.
    """
    # Convert each IPv6 address back to a hex string
    hex_data = ''.join([format(int(ipaddress.IPv6Address(addr)), '032x') for addr in ipv6_encoded_addresses])

    # Remove padding zeroes from the end
    hex_data = hex_data.rstrip('0')

    # Convert the hex data back to the original string
    ipv6_decoded_data = bytes.fromhex(hex_data).decode('utf-8')

    return ipv6_decoded_data
