import bcrypt
import pickle
import getpass


def compare_hash(operator: str, pw: str) -> bool:
    """
    Compares a password and a hash

    Parameters:
        pw (str): The password being compared
        operator (str): The operator to find the PW for

    Returns:
        bool: Returns true or false based on the comparison outcome
    """
    with open('users.pkl', 'rb') as file:
        # Dump the data into a local dict
        data = pickle.load(file)

    # Search the dict with the operator ID as the search key
    if data[operator] and operator in data:
        # Use bcrypt's built in method to check the password
        result = bcrypt.checkpw(bytes(pw, 'utf-8'), data[operator])
        if result is True:
            return True
        else:
            return False
    else:
        return False


def save_password(inpt_uname: str, inpt_pw) -> bool:
    """
    Adds a password to the store

    Parameters:
        inpt_uname (str): The operator name associated with the password
        inpt_pw (str): The password associated with the name

    Returns:
        bool: Bool indicating success or failure when storing the uname/pw
    """
    # Empty dict
    data = {}
    # Open the json file for users
    try:
        with open('users.pkl', 'rb') as file:
            # Dump the data into a local dict
            data = pickle.load(file)
    except Exception as e:
        print(f"No users exist yet: {e}")
        # If the dict is empty this will cause issues
        # First user creation needs to be handled specially
        salt = bcrypt.gensalt()
        hashedpw = bcrypt.hashpw(bytes(inpt_pw, 'utf-8'), salt)
        data[inpt_uname] = hashedpw

        # Save the new data
        try:
            with open('users.pkl', 'wb') as file:
                # Dump the data into a local dict
                pickle.dump(data, file)
                return True
        except Exception as e:
            return e

    # Check the operator name doesn't exist
    if inpt_uname not in data:
        salt = bcrypt.gensalt()
        hashedpw = bcrypt.hashpw(bytes(inpt_pw, 'utf-8'), salt)
        data[inpt_uname] = hashedpw

        # Save the new data
        try:
            with open('users.pkl', 'wb') as file:
                # Dump the data into a local dict
                pickle.dump(data, file)
                return True
        except Exception as e:
            return e
    else:
        return "Name exists, choose a different one"


if __name__ == "__main__":
    uname = input("Enter username to register:" )
    pw = getpass.getpass()
    result = save_password(uname, pw)
    if result is True:
        print("Registered user")
    else:
        print(result)
