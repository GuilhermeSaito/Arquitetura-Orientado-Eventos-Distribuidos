import pika
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Gerar chaves privadas e públicas para descriptografia
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

def save_public_key():
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("public_key.pem", "wb") as f:
        f.write(public_key_pem)

# Função para descriptografar a mensagem
def decrypt_message(encrypted_message):
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

# Setup do RabbitMQ
def setup_connection():
    connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
    channel = connection.channel()
    return connection, channel

# Inscrever-se para receber atualizações do leilão
def subscribe_to_updates(exchange_name):
    connection, channel = setup_connection()

    # Declarando a exchange
    channel.exchange_declare(exchange=exchange_name, exchange_type='fanout')

    # Criando uma fila temporária para o participante
    result = channel.queue_declare(queue='', exclusive=True)
    queue_name = result.method.queue

    # Ligando a fila à exchange
    channel.queue_bind(exchange=exchange_name, queue=queue_name)

    print(f" [*] Waiting for messages in {queue_name}. To exit press CTRL+C")

    # Função callback para processar mensagens recebidas
    def callback(ch, method, properties, body):
        # Descriptografando a mensagem
        decrypted_message = decrypt_message(body)
        print(f" [x] Received and decrypted: {decrypted_message}")

    # Consumir mensagens
    channel.basic_consume(queue=queue_name, on_message_callback=callback, auto_ack=True)

    channel.start_consuming()

if __name__ == "__main__":
    # Salva a chave publica para o participante poder criptografar o dado
    save_public_key()

    exchange = 'leilao_eventos'
    subscribe_to_updates(exchange)
