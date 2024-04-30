import sys
import cantools
import os
import pprint

def decode_can_message(can_id, data, dbc_path):
    """
    Decodes a CAN message using a DBC file.
    
    Parameters:
        can_id (int): The CAN ID of the message.
        data (bytes): The data of the CAN message as a bytes object.
        dbc_path (str): The path to the DBC file.
    
    Returns:
        dict: The decoded CAN message.
    """
    db = cantools.db.load_file(dbc_path)
    print(db.messages)
    # db.add_dbc_file(dbc_path)
    message = db.get_message_by_frame_id(can_id)
    decoded_message = message.decode(data)
    return decoded_message




can_id = int('700', 16)  # Convert CAN ID from hex string to integer
data_hex = '0000004140002000'  # Data as a hex string
dbc_path = os.path.join(os.path.curdir,'Mobileye.dbc')

# Convert the data hex string to a bytes object
data = bytes.fromhex(data_hex)
print(data)


# Decode the CAN message
decoded_message = decode_can_message(can_id, data, dbc_path)

# Print the decoded message
pprint.pprint(decoded_message)
