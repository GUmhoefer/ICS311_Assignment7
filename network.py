from user import User

class Network:
    def __init__(self):
        self.users = {}  # Dictionary of user objects with user.id as key
        self.public_keys = {}  # Dictionary of public keys with user.id as key
        self.edges = set()  # List of directed edges
        used_primes = set()  # Set of primes that have been used for RSA


    def add_user(self, user_id, friends):
        
        # Generate public and private key for user
        pub_key = None
        priv_key = None

        # Create user object and add it to network
        user = User(user_id, pub_key, priv_key, friends)

        # Adds unique edges between the user and their friends
        for friend in friends:
            self.edges.add(tuple(sorted((user_id, friend))))


    def encrypted_message(self, sender_id, receiver_id, message, metadata = None):
        # Create a message from sender to receiver with the given content
        message = (sender_id, receiver_id, {"metadata": metadata, "message": message})

    def encrypt(self, message, public_key):
        pass

    def generate_prime(self, bits):
        pass

    def primality_check(self, n):
        pass

    def mod_exp(self, base, exp, mod):
        pass

    def mult_inv(self, a, m):
        pass

    def ext_euclid(self, a, b):
        pass

    def sign_message(self, message, private_key):
        pass