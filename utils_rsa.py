from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import os

# global private_key_path
# private_key_path = "keys/private_key.pem"

# global public_key_path
# public_key_path = "keys/public_key.pem"


def gerar_arquivos_chaves(private_key_path: str, public_key_path: str):
    """
    Gera as chaves privada e pública e salva em arquivos .pem

    Args:
        private_key_path (str): Caminho para o arquivo .pem que receberá a chave privada
        public_key_path (str): Caminho para o arquivo .pem que receberá a chave pública

    Returns:
        Arquivos .pem com as chaves privada e pública

    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
        backend=default_backend(),
    )
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with open(private_key_path, "xb") as private_file:
        private_file.write(private_bytes)

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(public_key_path, "xb") as public_file:
        public_file.write(public_bytes)


def deserializar_chave_privada(private_key_path: str):
    """
    Deserializa a chave privada do arquivo .pem

    Args:
        private_key_path (str): Caminho para o arquivo .pem contendo a chave privada

    Returns:
        Chave privada deserializada

    """
    with open(private_key_path, "rb") as private_file:
        loaded_private_key = serialization.load_pem_private_key(
            private_file.read(), password=None, backend=default_backend()
        )
    return loaded_private_key


def deserializar_chave_publica(public_key_path: str):
    """
    Deserializa a chave publica do arquivo .pem

    Args:
        public_key_path (str): Caminho para o arquivo .pem contendo a chave publica

    Returns:
        Chave publica deserializada

    """
    with open(public_key_path, "rb") as public_file:
        loaded_public_key = serialization.load_pem_public_key(
            public_file.read(), backend=default_backend()
        )
    return loaded_public_key


def criptografar_com_chave_publica(data: bytes, public_key_path: str):
    """
    Criptografa um texto usando a chave pública

    Args:
        data (bytes): Dado a ser criptografado
        public_key_path (str): Caminho para o arquivo .pem contendo a chave pública

    Returns:
        Texto criptografado

    """
    loaded_public_key = deserializar_chave_publica(public_key_path)

    padding_config = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

    ciphertext = loaded_public_key.encrypt(
        plaintext=data,
        padding=padding_config,
    )

    return ciphertext


def descriptografar_com_chave_privada(data: bytes, private_key_path: str):
    """
    Descriptografa um texto usando a chave privada

    Args:
        data (bytes): Dado a ser criptografado
        private_key_path (str): Caminho para o arquivo .pem contendo a chave privada

    Returns:
        Texto descriptografado

    """
    loaded_private_key = deserializar_chave_privada(private_key_path)

    padding_config = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

    plaintext = loaded_private_key.decrypt(
        ciphertext=data,
        padding=padding_config,
    )

    return plaintext


def test_criptografia_rsa(data: str, private_key_path: str, public_key_path: str):

    print(f"Texto original: {data}\n")
    plaintext = data.encode("utf-8")

    for i in range(2):
        ciphertext = criptografar_com_chave_publica(plaintext, public_key_path)
        print(f"Texto criptografado {i}: {ciphertext}\n")
        print(f"Tamanho do texto criptografado {i}: {len(ciphertext)}\n")

    deciphertext = descriptografar_com_chave_privada(ciphertext, private_key_path)
    print(f"Texto descriptografado: {deciphertext.decode()}\n")


if __name__ == "__main__":
    print("\n---Iniciando teste de criptografia RSA---\n")

    private_key_path = "keys/private_key.pem"
    public_key_path = "keys/public_key.pem"
    if not os.path.isfile(private_key_path) and not os.path.isfile(public_key_path):
        gerar_arquivos_chaves()

    data = "Teste de criptografia RSA"
    test_criptografia_rsa(data, private_key_path, public_key_path)
