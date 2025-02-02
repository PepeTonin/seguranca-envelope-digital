import json
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from secrets import token_bytes


def gerar_iv():
    return token_bytes(16)


def gerar_chave():
    return token_bytes(32)


def decrypt_aes(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Descriptografa o texto cifrado usando AES no modo CBC.

    :param key: Chave de criptografia de 16, 24 ou 32 bytes.
    :param iv: Vetor de inicialização de 16 bytes.
    :param ciphertext: Texto cifrado a ser descriptografado.
    :return: Texto em claro.
    """
    # Criação do cifrador AES no modo CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Criando o objeto de descriptografia
    decryptor = cipher.decryptor()

    # Descriptografando o texto cifrado
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remoção do preenchimento
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext


def encrypt_aes(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """
    Criptografa o texto usando AES no modo CBC.
    :param key: Chave de criptografia de 16, 24 ou 32 bytes.
    :param iv: Vetor de inicialização de 16 bytes.
    :param plaintext: Texto em claro a ser criptografado.
    :return: Texto cifrado.
    """
    # Criação do cifrador AES no modo CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Criando o objeto de criptografia
    encryptor = cipher.encryptor()

    # Preenchimento do texto em claro para ajustar ao tamanho do bloco
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Criptografando o texto em claro
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return ciphertext


if __name__ == "__main__":
    print("\n---Iniciando teste de criptografia AES---\n")

    key = gerar_chave()
    print(f"Chave de criptografia: {key}\n")

    iv = gerar_iv()
    print(f"Vetor de inicialização: {iv}\n")

    plaintext = "Teste de criptografia AES"
    print(f"Texto original: {plaintext}\n")

    plaintext = plaintext.encode("utf-8")

    ciphertext = encrypt_aes(key, iv, plaintext)
    print(f"Texto criptografado: {ciphertext}\n")
    print(f"Tamanho do texto criptografado: {len(ciphertext)}\n")

    decrypted_data = decrypt_aes(key, iv, ciphertext)
    print(f"Texto descriptografado: {decrypted_data.decode()}\n")
