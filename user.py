
class User:
    def __init__(self, user_id, pub_key, priv_key, friends):
        self.id = user_id
        self.pub_key = pub_key
        self.priv_key = priv_key
        self.friends = friends

    def __str__(self):
        return (f"User {self.id} has friends {self.friends}"
                f"\nPublic key: {self.pub_key}"
                f"\nPrivate key: {self.priv_key}")