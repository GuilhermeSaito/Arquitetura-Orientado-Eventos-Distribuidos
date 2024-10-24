# leiloeiro.py

import pika
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# # Gerar chaves privadas e públicas para criptografia
# private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
# public_key = private_key.public_key()

# # Função para criptografar a mensagem
# def encrypt_message(message):
#     encrypted = public_key.encrypt(
#         message.encode(),
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     return encrypted

# Setup do RabbitMQ
def setup_connection():
    connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
    channel = connection.channel()
    return connection, channel

# Publicar mensagens do leiloeiro
def publish_message(exchange_name, message):
    connection, channel = setup_connection()

    # Declarando a exchange
    channel.exchange_declare(exchange=exchange_name, exchange_type='fanout')

    # Criptografando a mensagem
    # encrypted_message = encrypt_message(message)
    encrypted_message = message

    # Publicando a mensagem criptografada para todos os consumidores
    channel.basic_publish(exchange=exchange_name, routing_key='', body=encrypted_message)

    print(f" [x] Sent (encrypted): {encrypted_message}")
    connection.close()

if __name__ == "__main__":
    exchange = 'leilao_eventos'

    # Exemplo de eventos
    publish_message(exchange, 'Novo lance de 1000 para o item #123')
    publish_message(exchange, 'Atualização: Lance de 1500 para o item #123')
    publish_message(exchange, 'Leilão encerrado para o item #123')