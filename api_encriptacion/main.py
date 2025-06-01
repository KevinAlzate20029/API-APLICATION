from fastapi import FastAPI, Query
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

app = FastAPI()

# Generar par de claves (pública y privada)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

# Serializar las claves para mostrarlas
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode()

public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

@app.get("/encrypt")
def encrypt_message(message: str = Query(..., description="Mensaje a encriptar")):
    encrypted_data = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_text_b64 = base64.b64encode(encrypted_data).decode()

    return {
        "encrypted_message": encrypted_text_b64,
        "public_key": public_key_pem,
        "private_key": private_key_pem
    }
