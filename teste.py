import tempfile
import time

# Criando um arquivo temporário
with tempfile.NamedTemporaryFile() as temp_file:
    print("Arquivo temporário criado:", temp_file.name)
    
    # Executando o restante do código enquanto o arquivo existe
    print("Hello Another World")
    time.sleep(10)  # Simula o tempo de execução do programa

# O arquivo temporário é automaticamente apagado ao sair do bloco "with"
print("Arquivo temporário removido. Execução terminada.")
