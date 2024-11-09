import json
import base64  # Para codificar a assinatura em base64
import pika
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import threading  # Para criar a thread

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

# Função para assinar a mensagem
def sign_message(message):
    encrypted = private_key.sign(
        message.encode(),  # Convertendo a mensagem em bytes
        padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return encrypted

# Setup do RabbitMQ
def setup_connection():
    connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
    channel = connection.channel()
    return connection, channel

def create_exchange(exchange_name):
    connection, channel = setup_connection()

    # Declarando a exchange
    channel.exchange_declare(exchange=exchange_name, exchange_type='direct')

    return connection, channel

# Publicar mensagens do leiloeiro
def publish_message(exchange_name, message, routing_key):
    connection, channel = create_exchange(exchange_name)

    # Assinando a mensagem
    signed_message = sign_message(message)

    # Criando um objeto JSON contendo a mensagem original e a assinatura em base64
    message_payload = json.dumps({
        "original_message": message,
        "signed_message": base64.b64encode(signed_message).decode('utf-8'),
        "routing_key": routing_key
    })

    # Publicando a mensagem JSON
    channel.basic_publish(exchange=exchange_name, routing_key=routing_key, body=message_payload)

    print(f" [x] Sent (encrypted): {message_payload}")
    connection.close()

# Inscrever-se para receber atualizações do leiloeiro
def listen_for_updates():
    exchange_name = "lance_verification"
    connection, channel = create_exchange(exchange_name)

    # Criando uma fila temporária para o participante
    result = channel.queue_declare(queue='', exclusive=True)
    queue_name = result.method.queue

    # Ligando a fila à exchange com a routing_key específica
    routing_key = 'verificar_lance'
    channel.queue_bind(exchange=exchange_name, queue=queue_name, routing_key=routing_key)

    print(f" [*] Waiting for verification updates in {queue_name}. To exit press CTRL+C")

    # Função callback para processar mensagens recebidas
    def callback(ch, method, properties, body):
        # Desserializando o JSON
        data = json.loads(body)
        print(f" [x] Received update: {data['original_message']}")

    # Consumir mensagens
    channel.basic_consume(queue=queue_name, on_message_callback=callback, auto_ack=True)

    channel.start_consuming()

def listen_confirmation():
    exchange_name = "confirmation_message"
    connection, channel = create_exchange(exchange_name)

    # Criando uma fila temporária para o participante
    result = channel.queue_declare(queue='', exclusive=True)
    queue_name = result.method.queue

    # Ligando a fila à exchange com a routing_key específica
    routing_key = 'confirmation_message'
    channel.queue_bind(exchange=exchange_name, queue=queue_name, routing_key=routing_key)

    print(f" [*] Waiting for verification updates in {queue_name}. To exit press CTRL+C")

    # Função callback para processar mensagens recebidas
    def callback(ch, method, properties, body):
        # Desserializando o JSON
        data = json.loads(body)
        print(f" [x] Received update: {data}")

        connection.close()

    # Consumir mensagens
    channel.basic_consume(queue=queue_name, on_message_callback=callback, auto_ack=True)

    channel.start_consuming()

if __name__ == "__main__":
    exchange = 'leilao_eventos_direct'

    choice = 1

    while choice != 0:
        choice = int(input("Informe uma opcao:\n1 = Novo Lance.\n2 = Atualizar o lance.\n3 = Retirar Lance.\n4 = Verificar lance.\n0 = Sair\n: "))
        
        if choice != 0:
            name = input("Informe seu nome: ")
            lote = input("Insira o numero do lote: ")

            # Gera a chave publica para todos
            save_public_key()

        if choice == 1:
            valor = input("Insira o valor desejado para o lance: ")
            routing_key = 'novo_lance'
            publish_message(exchange, f"Novo lance de {valor} para o item {lote} da pessoa {name}", routing_key)

            listen_confirmation()

        elif choice == 2:
            valor = input("Insira o valor desejado para atualizar o lance: ")
            routing_key = 'atualizar_lance'
            publish_message(exchange, f"Atualizar lance de {valor} para o item {lote} da pessoa {name}", routing_key)

            listen_confirmation()

        elif choice == 3:
            routing_key = 'retirar_lance'
            publish_message(exchange, f"Retirar lance do item {lote} da pessoa {name}", routing_key)

            listen_confirmation()

        elif choice == 4:
            routing_key = 'verificar_lance'
            publish_message(exchange, f"Verificar lance do item {lote}", routing_key)

            # Inicia uma nova thread para escutar as atualizações de verificação
            update_thread = threading.Thread(target=listen_for_updates)
            update_thread.daemon = True  # Define como daemon para encerrar ao fechar o programa
            update_thread.start()

        else:
            break
