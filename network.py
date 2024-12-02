from user import User
import math
import random
import hashlib

class Network:
    def __init__(self):
        self.users = {}  # Dictionary of user objects with user.id as key
        self.public_keys = {}  # Dictionary of public keys with user.id as key
        self.edges = set()  # Set of edges between users
        self.used_primes = set()  # Set of primes that have been used for RSA


    def add_user(self, user_id, friends):
        
        # Generate RSA keys for user
        pub_key, priv_key = self.generate_rsa_keys()

        # Create user object and add it to network
        user = User(user_id, pub_key, priv_key, friends)
        self.users[user_id] = user

        # Adds unique edges between the user and their friends
        for friend in friends:
            self.edges.add(tuple(sorted((user_id, friend))))
    
    def encrypt_message(self, sender_id, receiver_id, message, metadata=None):
        # Sign the message using the sender's private key
        signature = self.sign_message(message, self.users[sender_id].priv_key)
        
        # Encrypt the message using the receiver's public key
        encrypted_message = self.encrypt(message, self.users[receiver_id].pub_key)
        
        # Return the signed and encrypted message
        return (sender_id, receiver_id, {"metadata": metadata, "message": encrypted_message, "signature": signature})

    def decrypt_message(self, message):
        sender_id, receiver_id, body = message
        
        # Decrypt the message
        decrypted_message = self.decrypt(body["message"], self.users[receiver_id].priv_key)
        
        # Verify the signature
        is_valid = self.verify_signature(decrypted_message, body["signature"], self.users[sender_id].pub_key)
        
        if not is_valid:
            raise ValueError("Signature verification failed! The message may have been tampered with.")
        
        # Return the decrypted and validated message
        return decrypted_message

    def encrypt(self, message, key):
        encoded_bytes = message.encode('utf-8')
        encoded_int = int.from_bytes(encoded_bytes, byteorder='big')
        encrypted_int = self.mod_exp(encoded_int, key[1], key[0])
        return encrypted_int

    def decrypt(self, message, key):
        
        try:
            decrypted_int = self.mod_exp(message, key[1], key[0])

            # Adds 7 bits of padding to bit length to ensure proper rounding to bytes with integer division by 8
            decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, byteorder='big')
            decrypted_message = decrypted_bytes.decode('utf-8')
            return decrypted_message
        except UnicodeDecodeError as e:
            print("Incorrect key used for decryption: ", e)
            
    def generate_rsa_keys(self):
        """
        Generates public and private RSA keys.
        """

        # Generate two distinct prime numbers
        p = self.generate_prime()
        q = self.generate_prime()

        # Calculate n = p * q
        n = p * q

        # Calculate Euler's totient phi(n)
        phi = (p - 1) * (q - 1)

        # Generate public and private exponents
        e, d = self.get_exponents(phi)

        return (n, e), (n, d)

    def generate_prime(self, bits = 512):
        while True:
            # Generates a random odd number with specifid bit length
            n = random.randrange(2 ** (bits - 1) + 1, 2 ** bits - 1, 2)

            # Checks if the number is prime and has not been used before
            if self.primality_check(n) and n not in self.used_primes:
                self.used_primes.add(n)
                return n

    def primality_check(self, n, s = 3):
        """
        Uses the Miller-Rabin primality test to check if a number is prime.
        """

        # Decompose n - 1 into the binary representation 2^t * u
        # Continuously divides u by 2 until u is odd, t is the number of times this occurs.
        t = 0
        u = n - 1
        while u % 2 == 0:
            t += 1
            u = u // 2
        
        # Run the primality test s times
        for i in range(s):
            a = random.randint(2, n - 2) # Calculates random base to test if n is composite

            # Calculate a^u mod n using fast modular exponentiation
            x = self.mod_exp(a, u, n)

            for i in range(t):
                x0 = x
                x = self.mod_exp(x, 2, n)
                if x == 1 and x0 != 1 and x0 != n - 1:
                    return False
            if x != 1:
                return False
            return True

    def mod_exp(self, a, b, n):
        if b == 0:
            return 1
        elif b % 2 == 0:
            d = self.mod_exp(a, b // 2, n)
            return (d * d) % n
        else:
            d = self.mod_exp(a, b - 1, n)
            return (a * d) % n

    def get_exponents(self, phi):
        """
        Starts with a standard public exponent of 65537 and determines if it
        is relatively prime with phi(n). If it is not, increments to the next odd
        number until it is. Then returns the public exponent and its multiplicative
        inverse, the private exponent.
        """
        while True:
            e = 65537 # Commonly used RSA public exponent
            d, x, y = self.ext_euclid(e, phi)
            if d == 1:
                x = x % phi
                return e, x
            else:
                e += 2 # Increment by 2 to keep e odd

    def ext_euclid(self, a, b):
        if b == 0:
            return (a, 1, 0)
        else:
            d1, x1, y1 = self.ext_euclid(b, a % b)
            d = d1
            x = y1
            y = x1 - (a // b) * y1
            return (d, x, y)

    def sign_message(self, message, priv_key):
        # Hash the message using SHA-256
        message_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()
        
        # Convert the hash to an integer
        hash_int = int(message_hash, 16)
        
        # Sign the hash by encrypting it with the sender's private key
        signature = self.mod_exp(hash_int, priv_key[1], priv_key[0])
        
        return signature

    def verify_signature(self, message, signature, pub_key):
        # Decrypt the signature using the sender's public key
        decrypted_hash_int = self.mod_exp(signature, pub_key[1], pub_key[0])
        
        # Hash the message using SHA-256
        message_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()
        hash_int = int(message_hash, 16)
        
        # Compare the decrypted hash with the recomputed hash
        return decrypted_hash_int == hash_int