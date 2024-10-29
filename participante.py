import pika
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# Função para criptografar a mensagem
def encrypt_message(message):
    # Resgatando a chave publica criada pelo leiloeiro
    with open("public_key.pem", "rb") as f:
        public_key_pem = f.read()
        public_key = serialization.load_pem_public_key(public_key_pem)

    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

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
    encrypted_message = encrypt_message(message)
    # encrypted_message = message

    # Publicando a mensagem criptografada para todos os consumidores, como o type do exchange eh fanout = broadcast, ignora o routing_key
    channel.basic_publish(exchange=exchange_name, routing_key='', body=encrypted_message)

    print(f" [x] Sent (encrypted): {encrypted_message}")
    connection.close()

if __name__ == "__main__":
    exchange = 'leilao_eventos'

    choice = 1

    while choice != 0:
        choice = int(input("Informe uma opcao:\n1 = Novo Lance.\n2 = Atualizar o lance.\n3 = Retirar Lance.\n4 = Verificar lance.\n0 = Sair\n: "))
        
        if choice != 0:
            name = input("Informe seu nome: ")
            lote = input("Insira o numero do lote: ")

        if choice == 1:
            valor = input("Insira o valor desejado para o lance: ")

            publish_message(exchange, f"Novo lance de {valor} para o item {lote} da pessoa {name}")

        elif choice == 2:
            valor = input("Insira o valor desejado para atualizar o lance: ")

            publish_message(exchange, f"Atualizar lance de {valor} para o item {lote} da pessoa {name}")

        elif choice == 3:
            publish_message(exchange, f"Retirar lance do item {lote} da pessoa {name}")

        elif choice == 4:
            publish_message(exchange, f"Verificar lance do item {lote}")

        else:
            break


    # Exemplo de eventos
    # publish_message(exchange, 'Novo lance de 1000 para o item #123')
    # publish_message(exchange, 'Atualização: Lance de 1500 para o item #123')
    # publish_message(exchange, 'Leilão encerrado para o item #123')