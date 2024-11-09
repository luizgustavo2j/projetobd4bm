import bcrypt
import pyotp
from pymongo import MongoClient
from cryptography.fernet import Fernet
import base64
from bson.objectid import ObjectId
import tkinter as tk
from tkinter import messagebox, simpledialog

# Conexão com o MongoDB Atlas
def obter_banco_de_dados():
    cliente = MongoClient("mongodb+srv://batatatata361:BDfzKBwBrfH5nSR@clusterescola.zagsh.mongodb.net/?retryWrites=true&w=majority&appName=ClusterEscola")
    banco = cliente['ProjetoMongoBruno']  # substitua pelo nome do seu banco
    return banco

banco = obter_banco_de_dados()

# Funções de Autenticação e Controle de Acesso
def hash_senha(senha):
    hashed = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())
    return base64.b64encode(hashed).decode('utf-8')

def verificar_senha(senha_armazenada, senha_fornecida):
    senha_armazenada = base64.b64decode(senha_armazenada.encode('utf-8'))
    return bcrypt.checkpw(senha_fornecida.encode('utf-8'), senha_armazenada)

def gerar_segredo_2fa():
    return pyotp.random_base32()

def obter_token_otp(segredo):
    totp = pyotp.TOTP(segredo)
    return totp.now()

def verificar_otp(segredo, token):
    return segredo == token

def registrar_usuario(nome_usuario, senha):
    usuario = {
        "nome_usuario": nome_usuario,
        "senha": hash_senha(senha),
        "segredo_2fa": gerar_segredo_2fa()
    }
    banco.usuarios.insert_one(usuario)
    return usuario['segredo_2fa']  # Retorna o segredo para exibição

def autenticar_usuario(nome_usuario, senha, token):
    usuario = banco.usuarios.find_one({"nome_usuario": nome_usuario})
    
    if not usuario:
        print("Usuário não encontrado.")
        return False

    if not verificar_senha(usuario['senha'], senha):
        print("Senha incorreta.")
        return False

    segredo_2fa = usuario['segredo_2fa']
    if not verificar_otp(segredo_2fa, token):
        print("Token 2FA incorreto.")
        return False

    print("Autenticação bem-sucedida.")
    return True

# Funções de Criptografia e Descriptografia
def gerar_chave():
    return Fernet.generate_key()

def criptografar_dados(dados, chave):
    fernet = Fernet(chave)
    return fernet.encrypt(dados.encode())

def descriptografar_dados(dados_criptografados, chave):
    fernet = Fernet(chave)
    return fernet.decrypt(dados_criptografados).decode()

# Funções Principais
def criar_registro(nome_usuario, senha, token, nome_paciente, historico_medico, tratamento, nome_do_medico):
    if not autenticar_usuario(nome_usuario, senha, token):
        return "Acesso negado: falha na autenticação."
    
    chave = gerar_chave()  # Gerar chave para criptografia
    registro_criptografado = {
        "nome_paciente": criptografar_dados(nome_paciente, chave),
        "historico_medico": criptografar_dados(historico_medico, chave),
        "tratamento": criptografar_dados(tratamento, chave),
        "nome_do_medico": nome_do_medico  # Armazenar o nome do médico
    }
    
    banco.registros.insert_one(registro_criptografado)
    return "Registro médico criado com sucesso."

def visualizar_registro(nome_usuario, senha, token):
    if not autenticar_usuario(nome_usuario, senha, token):
        return "Acesso negado: falha na autenticação."
    
    # Encontrar todos os registros associados ao médico
    registros = list(banco.registros.find({"nome_do_medico": nome_usuario}))  # Usar nome_do medico como filtro
    if not registros:
        return "Nenhum registro encontrado para este médico."
    
    registros_dados = []
    for registro in registros:
        chave = base64.b64decode(registro["chave"])
        nome_paciente = descriptografar_dados(registro["nome_paciente"], chave)
        historico_medico = descriptografar_dados(registro["historico_medico"], chave)
        tratamento = descriptografar_dados(registro["tratamento"], chave)
        registros_dados.append({
            "_id": registro["_id"],
            "nome_paciente": nome_paciente,
            "historico_medico": historico_medico,
            "tratamento": tratamento
        })
    
    return registros_dados

def inicializar_interface(master):
    master.title("Sistema de Registro Médico")

    label = tk.Label(master, text="Escolha uma operação:")
    label.pack(pady=10)

    registrar_button = tk.Button(master, text="Registrar Usuário", command=registrar_usuario_tk)
    registrar_button.pack(pady=5)

    criar_button = tk.Button(master, text="Criar Registro Médico", command=criar_registro_tk)
    criar_button.pack(pady=5)

    visualizar_button = tk.Button(master, text="Visualizar Registro Médico", command=visualizar_registro_tk)
    visualizar_button.pack(pady=5)

def exibir_segredo_2fa(segredo):
    janela_2fa = tk.Toplevel()
    janela_2fa.title("Segredo 2FA")

    label = tk.Label(janela_2fa, text="Segredo 2FA (copie e adicione ao seu aplicativo de autenticação):")
    label.pack(pady=5)

    text_2fa = tk.Text(janela_2fa, height=1, width=30)
    text_2fa.insert(tk.END, segredo)
    text_2fa.config(state="disabled")
    text_2fa.pack(pady=5)

    fechar_button = tk.Button(janela_2fa, text="Fechar", command=janela_2fa.destroy)
    fechar_button.pack(pady=5)

def registrar_usuario_tk():
    nome_usuario = simpledialog.askstring("Registrar Usuário", "Digite o nome de usuário:")
    senha = simpledialog.askstring("Registrar Usuário", "Digite a senha:", show='*')
    
    if nome_usuario and senha:
        segredo_2fa = registrar_usuario(nome_usuario, senha)
        messagebox.showinfo("Sucesso", f"Usuário {nome_usuario} registrado com sucesso.")
        
        exibir_segredo_2fa(segredo_2fa)

def criar_registro_tk():
    nome_usuario = simpledialog.askstring("Criar Registro", "Digite o nome de usuário:")
    senha = simpledialog.askstring("Criar Registro", "Digite a senha:", show='*')
    token = simpledialog.askstring("Criar Registro", "Digite o código 2FA:")
    nome_paciente = simpledialog.askstring("Criar Registro", "Digite o nome do paciente:")
    historico_medico = simpledialog.askstring("Criar Registro", "Digite o histórico médico:")
    tratamento = simpledialog.askstring("Criar Registro", "Digite o tratamento:")
    nome_do_medico = simpledialog.askstring("Criar Registro", "Digite seu nome como médico:")
        
    resultado = criar_registro(nome_usuario, senha, token, nome_paciente, historico_medico, tratamento, nome_do_medico)
    messagebox.showinfo("Resultado", resultado)

def exibir_detalhes_registro(registro):
    detalhes_janela = tk.Toplevel()
    detalhes_janela.title("Detalhes do Registro")

    label = tk.Label(detalhes_janela, text=f"Nome Paciente: {registro['nome_paciente']}\n"
                                            f"Histórico Médico: {registro['historico_medico']}\n"
                                            f"Tratamento: {registro['tratamento']}")
    label.pack(pady=5)

    fechar_button = tk.Button(detalhes_janela, text="Fechar", command=detalhes_janela.destroy)
    fechar_button.pack(pady=5)

def visualizar_registro_tk():
    nome_usuario = simpledialog.askstring("Visualizar Registro", "Digite o nome de usuário:")
    senha = simpledialog.askstring("Visualizar Registro", "Digite a senha:", show='*')
    token = simpledialog.askstring("Visualizar Registro", "Digite o código 2FA:")
        
    registros = visualizar_registro(nome_usuario, senha, token)
    
    if isinstance(registros, list):
        janela_registros = tk.Toplevel()
        janela_registros.title("Registros Médicos")

        label = tk.Label(janela_registros, text="Selecione um registro para visualizar:")
        label.pack(pady=5)

        for registro in registros:
            button = tk.Button(janela_registros, text=f"ID: {registro['_id']} - Paciente: {registro['nome_paciente']}",
                               command=lambda r=registro: exibir_detalhes_registro(r))
            button.pack(pady=2)

        fechar_button = tk.Button(janela_registros, text="Fechar", command=janela_registros.destroy)
        fechar_button.pack(pady=5)
    else:
        messagebox.showwarning("Erro", registros)

if __name__ == "__main__":
    root = tk.Tk()
    inicializar_interface(root)
    root.mainloop()
