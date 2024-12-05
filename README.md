# ICS 311 Assignment 7 Encryption and Signing

Please contact gregoru@hawaii.edu if there are any problems or for questions about running the program.

There are 3 files in the repository, please use network_driver.ipynb to run the network.py class methods.
* network.py
* user.py
* network_driver.ipynb

To create a network:

network_name = net.Network()

To add a user:

network_name.add_user("Username", [List of friends' usernames])

To send an encrypted and sign a message:

message = "Text of message"

encrypted_message = network_name.encrypt_message("Sender username", "Receiver username", message)

encrypted_message will contain:

("Sender", "Receiver", {"Metadata": metadata}, "message": message, "signature": signature)

To decrypt and verify a message:

decrypted_message = network_name.decrypt_message(encrypted_message)
