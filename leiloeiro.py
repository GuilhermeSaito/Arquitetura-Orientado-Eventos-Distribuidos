import json
import base64  # Para decodificar a assinatura de base64
import pika
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# Função para verificar a assinatura da mensagem
def verify_message(original_message, signed_message):
    # Resgatando a chave pública criada pelo leiloeiro
    with open("public_key.pem", "rb") as f:
        public_key_pem = f.read()
        public_key = serialization.load_pem_public_key(public_key_pem)

    # Verificando a assinatura
    try:
        public_key.verify(
            signed_message,
            original_message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return "Mensagem verificada com sucesso."
    except Exception as e:
        return f"Falha na verificação da mensagem: {e}"

# Setup do RabbitMQ
def setup_connection():
    connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
    channel = connection.channel()
    return connection, channel

# Inscrever-se para receber atualizações do leilão
def subscribe_to_updates(exchange_name):
    connection, channel = setup_connection()

    # Declarando a exchange
    channel.exchange_declare(exchange=exchange_name, exchange_type='direct')

    # Criando uma fila temporária para o participante
    result = channel.queue_declare(queue='', exclusive=True)
    queue_name = result.method.queue

    # Ligando a fila à exchange com diferentes routing_keys
    routing_keys = ['novo_lance', 'atualizar_lance', 'retirar_lance', 'verificar_lance']
    for routing_key in routing_keys:
        channel.queue_bind(exchange=exchange_name, queue=queue_name, routing_key=routing_key)

    print(f" [*] Waiting for messages in {queue_name}. To exit press CTRL+C")

    # Função callback para processar mensagens recebidas
    def callback(ch, method, properties, body):
        # Desserializando o JSON
        data = json.loads(body)
        original_message = data["original_message"]
        signed_message = base64.b64decode(data["signed_message"])

        # Verificando a mensagem recebida
        verification_result = verify_message(original_message, signed_message)
        print(f" [x] Received and verified: {verification_result}")

    # Consumir mensagens
    channel.basic_consume(queue=queue_name, on_message_callback=callback, auto_ack=True)

    channel.start_consuming()

if __name__ == "__main__":
    exchange = 'leilao_eventos_direct'
    subscribe_to_updates(exchange)
