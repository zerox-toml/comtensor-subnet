import hashlib
import time
from typing import Optional, Tuple
import bittensor as bt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

class SecurityManager:
    def __init__(self):
        self._private_key = None
        self._public_key = None
        self._nonce_cache = set()
        self._nonce_expiry = 300  # 5 minutes

    def generate_keypair(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate a new RSA keypair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        self._private_key = private_key
        self._public_key = public_key
        return private_key, public_key

    def sign_message(self, message: str, hotkey: bt.Keypair) -> str:
        """Sign a message using the Bittensor hotkey."""
        try:
            signature = hotkey.sign(message.encode()).hex()
            return signature
        except Exception as e:
            bt.logging.error(f"Failed to sign message: {e}")
            raise

    def verify_signature(self, message: str, signature: str, hotkey: str) -> bool:
        """Verify a signature using the Bittensor hotkey."""
        try:
            # Convert hex signature back to bytes
            signature_bytes = bytes.fromhex(signature)
            # Verify using Bittensor's verification
            return bt.Keypair(ss58_address=hotkey).verify(message.encode(), signature_bytes)
        except Exception as e:
            bt.logging.error(f"Failed to verify signature: {e}")
            return False

    def generate_nonce(self) -> str:
        """Generate a unique nonce."""
        nonce = hashlib.sha256(str(time.time()).encode()).hexdigest()
        self._nonce_cache.add(nonce)
        return nonce

    def verify_nonce(self, nonce: str) -> bool:
        """Verify if a nonce is valid and not expired."""
        if nonce in self._nonce_cache:
            self._nonce_cache.remove(nonce)
            return True
        return False

    def cleanup_expired_nonces(self):
        """Clean up expired nonces from the cache."""
        current_time = time.time()
        self._nonce_cache = {
            nonce for nonce in self._nonce_cache
            if current_time - float(nonce) < self._nonce_expiry
        }

    def encrypt_data(self, data: str, public_key: rsa.RSAPublicKey) -> bytes:
        """Encrypt data using RSA public key."""
        try:
            return public_key.encrypt(
                data.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            bt.logging.error(f"Failed to encrypt data: {e}")
            raise

    def decrypt_data(self, encrypted_data: bytes) -> str:
        """Decrypt data using RSA private key."""
        if not self._private_key:
            raise ValueError("No private key available for decryption")
        try:
            decrypted = self._private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.decode()
        except Exception as e:
            bt.logging.error(f"Failed to decrypt data: {e}")
            raise 