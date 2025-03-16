import hashlib
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.exceptions import InvalidSignature
from dataclasses import dataclass
from typing import List, Optional, Dict
import base64

@dataclass
class Certificate:
    subject: str
    issuer: str
    public_key: bytes
    signature: bytes
    valid_from: float
    valid_until: float

@dataclass
class SecureMessage:
    payload: bytes
    signature: bytes
    timestamp: float
    sequence_number: int
    sender_cert: Optional[bytes] = None

class CryptoModule:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.certificate = None
        self.message_history: Dict[str, List[tuple]] = {}  # (timestamp, sequence_number, hash)
        
    def generate_key_pair(self, use_ecdsa: bool = True) -> bool:
        """Generate a new key pair using either ECDSA or RSA."""
        try:
            if use_ecdsa:
                self.private_key = ec.generate_private_key(ec.SECP256K1())
                self.public_key = self.private_key.public_key()
            else:
                self.private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                self.public_key = self.private_key.public_key()
            return True
        except Exception as e:
            print(f"Key generation failed: {e}")
            return False

    def hash_message(self, message: bytes, algorithm: str = 'sha256') -> bytes:
        """Hash a message using the specified algorithm."""
        if algorithm == 'sha256':
            return hashlib.sha256(message).digest()
        elif algorithm == 'md5':
            return hashlib.md5(message).digest()
        elif algorithm == 'sha1':
            return hashlib.sha1(message).digest()
        elif algorithm == 'blake2b':
            return hashlib.blake2b(message).digest()
        elif algorithm == 'sha3_256':
            return hashlib.sha3_256(message).digest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    def sign_message(self, message: bytes) -> bytes:
        """Sign a message using the private key."""
        if not self.private_key:
            raise ValueError("Private key not available")

        try:
            if isinstance(self.private_key, rsa.RSAPrivateKey):
                signature = self.private_key.sign(
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            else:  # ECDSA
                signature = self.private_key.sign(
                    message,
                    ec.ECDSA(hashes.SHA256())
                )
            return signature
        except Exception as e:
            print(f"Message signing failed: {e}")
            return b""

    def verify_signature(self, message: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
        """Verify a message signature using a public key."""
        if not signature or not message:
            return False
            
        try:
            # Deserialize public key
            try:
                if b'BEGIN PUBLIC KEY' in public_key_bytes:
                    public_key = serialization.load_pem_public_key(public_key_bytes)
                else:
                    public_key = serialization.load_der_public_key(public_key_bytes)
            except Exception:
                # If deserialization fails, try using our own public key
                public_key = self.public_key

            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            else:  # ECDSA
                public_key.verify(
                    signature,
                    message,
                    ec.ECDSA(hashes.SHA256())
                )
            return True
        except (InvalidSignature, Exception) as e:
            print(f"Signature verification failed: {e}")
            return False

    def create_secure_message(self, payload: bytes) -> SecureMessage:
        """Create a secure message with signature and metadata."""
        if not payload:
            raise ValueError("Empty payload")
            
        timestamp = time.time()
        sequence_number = len(self.message_history.get(str(self.public_key), [])) + 1
        
        # Combine payload with metadata for signing
        message_data = payload + str(timestamp).encode() + str(sequence_number).encode()
        signature = self.sign_message(message_data)
        
        if not signature:
            raise ValueError("Failed to sign message")
        
        # Create secure message
        secure_msg = SecureMessage(
            payload=payload,
            signature=signature,
            timestamp=timestamp,
            sequence_number=sequence_number
        )
        
        # Add certificate if available
        if self.certificate:
            secure_msg.sender_cert = self.certificate
            
        # Update message history
        if str(self.public_key) not in self.message_history:
            self.message_history[str(self.public_key)] = []
        self.message_history[str(self.public_key)].append(
            (timestamp, sequence_number, self.hash_message(payload))
        )
        
        return secure_msg

    def verify_secure_message(self, message: SecureMessage) -> bool:
        """Verify a secure message's integrity and authenticity."""
        try:
            # Check timestamp (5 second tolerance)
            if abs(time.time() - message.timestamp) > 5:
                return False
                
            # Check for replay
            if self.is_replay_message(message):
                return False
                
            # Verify certificate if present
            if message.sender_cert:
                cert = self._deserialize_certificate(message.sender_cert)
                if not self._verify_certificate(cert):
                    return False
            
            # Combine message data for verification
            message_data = message.payload + str(message.timestamp).encode() + str(message.sequence_number).encode()
            
            # Get public key for verification
            public_key_bytes = message.sender_cert if message.sender_cert else (
                self.public_key.public_bytes(
                    encoding=Encoding.DER,
                    format=PublicFormat.SubjectPublicKeyInfo
                ) if self.public_key else None
            )
            
            if not public_key_bytes:
                return False
                
            return self.verify_signature(message_data, message.signature, public_key_bytes)
        except Exception as e:
            print(f"Message verification failed: {e}")
            return False

    def is_replay_message(self, message: SecureMessage) -> bool:
        """Check if a message is a replay attack."""
        for timestamp, seq, msg_hash in self.message_history.get(str(self.public_key), []):
            if (message.timestamp == timestamp and 
                message.sequence_number == seq and 
                self.hash_message(message.payload) == msg_hash):
                return True
        return False

    def _deserialize_certificate(self, cert_bytes: bytes) -> Certificate:
        """Deserialize a certificate from bytes."""
        # Implementation depends on your certificate format
        # This is a simplified example
        return Certificate(
            subject="test",
            issuer="test",
            public_key=cert_bytes,
            signature=b"",
            valid_from=time.time(),
            valid_until=time.time() + 3600
        )

    def _verify_certificate(self, cert: Certificate) -> bool:
        """Verify a certificate's validity."""
        current_time = time.time()
        return cert.valid_from <= current_time <= cert.valid_until 