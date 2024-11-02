import os
from utils_aes import encrypt_aes, decrypt_aes, gerar_chave, gerar_iv
from utils_rsa import (
    criptografar_com_chave_publica,
    descriptografar_com_chave_privada,
    gerar_arquivos_chaves,
)


def criar_envelope_digital(data: str, path_public_key_dest: str) -> dict:
    data = data.encode("utf-8")

    aes_key = gerar_chave()
    aes_iv = gerar_iv()

    encrypted_data = encrypt_aes(aes_key, aes_iv, data)

    session_key = criptografar_com_chave_publica(aes_key, path_public_key_dest)

    request_body = {
        "data": encrypted_data,
        "session_key": session_key,
        "iv": aes_iv,
    }

    return request_body


def ler_envelope_digital(request_body: dict, path_private_key_src: str) -> str:

    encrypted_data = request_body["data"]
    session_key = request_body["session_key"]
    aes_iv = request_body["iv"]

    aes_key = descriptografar_com_chave_privada(session_key, path_private_key_src)

    decrypted_data = decrypt_aes(aes_key, aes_iv, encrypted_data)

    return decrypted_data.decode("utf-8")


if __name__ == "__main__":
    print("\n---Iniciando teste de envelope digital---\n")

    private_key_path = "keys/private_key.pem"
    public_key_path = "keys/public_key.pem"
    if not os.path.isfile(private_key_path) and not os.path.isfile(public_key_path):
        gerar_arquivos_chaves(private_key_path, public_key_path)

    data = "Teste do envelope digital"
    print(f"Texto original: {data}\n")

    request_body = criar_envelope_digital(data, public_key_path)
    print(f"Envelope digital: {request_body}\n")

    decrypted_data = ler_envelope_digital(request_body, private_key_path)
    print(f"Texto descriptografado: {decrypted_data}\n")
