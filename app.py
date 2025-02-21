from flask import Flask, json, request, jsonify, redirect, session
import sqlite3
import requests
import logging
from hotmart_python import Hotmart
from werkzeug.serving import WSGIRequestHandler
from pyngrok import ngrok  # Para criar o túnel público com ngrok
from flask_cors import CORS  # Para configurar o CORS

WSGIRequestHandler.protocol_version = "HTTP/1.1" 
logging.getLogger('werkzeug').setLevel(logging.DEBUG)
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Habilitar CORS para todas as rotas
CORS(app, supports_credentials=True)

# Função para conectar ao banco de dados SQLite
def get_db_connection():
    conn = sqlite3.connect('meu_banco.db')
    conn.row_factory = sqlite3.Row  # Para que possamos acessar as colunas pelo nome
    return conn

FACEBOOK_APP_ID = "583564801061673"
FACEBOOK_APP_SECRET = "8a7513d13320c4097bd4a99ef6e11c68"
FACEBOOK_REDIRECT_URI = None  # Será configurado dinamicamente após iniciar o ngrok
    
@app.route('/api/cadastrar-empresa-cliente', methods=['POST'])
def cadastrar_empresa_cliente():
    try:
        data = request.get_json()
        email = data.get('email')
        empresa_nome = data.get('empresa')
        cliente_nome = data.get('cliente')
        telefone = data.get('telefone')

        # Validação dos campos obrigatórios
        if not all([email, empresa_nome, cliente_nome, telefone]):
            return jsonify({'message': 'Todos os campos são obrigatórios!'}), 400

        # Validação do telefone
        if not telefone.isdigit() or len(telefone) not in [10, 11]:
            return jsonify({'message': 'Número de telefone inválido. O telefone deve ter 10 ou 11 dígitos.'}), 400

        with sqlite3.connect('meu_banco.db') as conn:
            cursor = conn.cursor()

            # Obter o ID do usuário logado
            cursor.execute('SELECT id FROM usuarios WHERE email = ?', (email,))
            user = cursor.fetchone()

            if not user:
                return jsonify({'message': 'Usuário não encontrado!'}), 404

            user_id = user[0]

            # Inserir empresa
            cursor.execute(
                'INSERT INTO empresas (nome, usuario_id) VALUES (?, ?)',
                (empresa_nome, user_id)
            )
            empresa_id = cursor.lastrowid

            # Inserir cliente vinculado à empresa
            cursor.execute(
                'INSERT INTO clientes (nome, telefone, empresa_id) VALUES (?, ?, ?)',
                (cliente_nome, telefone, empresa_id)
            )
            conn.commit()

        return jsonify({'message': 'Empresa e cliente cadastrados com sucesso!'}), 201

    except sqlite3.DatabaseError as db_err:
        print(f"Erro de banco de dados: {db_err}")
        return jsonify({'message': 'Erro no banco de dados!'}), 500

    except Exception as e:
        print(f"Erro inesperado: {e}")
        return jsonify({'message': 'Erro no servidor!'}), 500

@app.route('/api/consultar-empresa-cliente', methods=['POST'])
def consultar_empresa_cliente():
    try:
        # Captura os dados enviados no corpo da requisição em formato JSON
        data = request.get_json()
        email = data.get('email') if data else None
        facebook_id = data.get('facebook_id') if data else None

        if not email and not facebook_id:
            return jsonify({'message': 'E-mail ou Facebook ID são obrigatórios!'}), 400

        # A consulta agora será feita com base nos dados fornecidos: email ou facebook_id
        with sqlite3.connect('meu_banco.db') as conn:
            cursor = conn.cursor()

            user = None
            if email:
                # Tenta localizar o usuário pelo e-mail
                cursor.execute('SELECT id, email FROM usuarios WHERE TRIM(email) = ?', (email,))
                user = cursor.fetchone()

            # Se não encontrar pelo e-mail, tenta encontrar pelo Facebook ID
            if not user and facebook_id:
                cursor.execute('SELECT id, email FROM usuarios WHERE facebook_id = ?', (facebook_id,))
                user = cursor.fetchone()

            if not user:
                return jsonify({'message': 'Usuário não encontrado!'}), 404

            user_id = user[0]

            # Obter empresas vinculadas ao ID do usuário na tabela 'empresas'
            cursor.execute('SELECT id, nome FROM empresas WHERE usuario_id = ?', (user_id,))
            empresas = cursor.fetchall()

            if not empresas:
                return jsonify({'message': 'Nenhuma empresa encontrada para este usuário!'}), 404

            resultado = []
            for empresa_id, empresa_nome in empresas:
                # Obter clientes vinculados à empresa
                cursor.execute('SELECT nome, telefone FROM clientes WHERE empresa_id = ?', (empresa_id,))
                clientes = cursor.fetchall()

                resultado.append({
                    'empresa_id': empresa_id,
                    'empresa_nome': empresa_nome,
                    'clientes': [{'nome': cliente[0], 'telefone': cliente[1]} for cliente in clientes]
                })

        # Retorna os dados das empresas e clientes para o frontend
        return jsonify(resultado), 200

    except sqlite3.DatabaseError as db_err:
        print(f"Erro de banco de dados: {db_err}")
        return jsonify({'message': 'Erro no banco de dados!'}), 500

    except Exception as e:
        print(f"Erro inesperado: {e}")
        return jsonify({'message': 'Erro no servidor!'}), 500

@app.route('/api/register', methods=['POST'])
def register_user():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({'message': 'E-mail e senha são obrigatórios!'}), 400

        conn = sqlite3.connect('meu_banco.db')
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM usuarios WHERE email = ?', (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'message': 'E-mail já cadastrado!'}), 409

        cursor.execute('INSERT INTO usuarios (email, senha) VALUES (?, ?)', (email, password))
        conn.commit()
        conn.close()

        return jsonify({'message': 'Usuário cadastrado com sucesso!'}), 201

    except Exception as e:
        print(f"Erro no registro: {e}")
        return jsonify({'message': 'Erro no servidor!'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('username')
        password = data.get('password')

        if not email or not password:
            return jsonify({'message': 'Usuário e senha são obrigatórios!'}), 400

        conn = sqlite3.connect('meu_banco.db')
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM usuarios WHERE email = ? AND senha = ?', (email, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            return jsonify({'message': 'Login realizado com sucesso!'}), 200
        else:
            return jsonify({'message': 'Usuário ou senha incorretos!'}), 401

    except Exception as e:
        print(f"Erro ao autenticar: {e}")
        return jsonify({'message': 'Erro no servidor!'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    try:
        # Receber o token de autenticação do cliente
        data = request.get_json()
        token = data.get('token')

        if not token:
            return jsonify({'message': 'Token é obrigatório para logout!'}), 400

        # Remover o token do banco de dados para efetuar o logout
        with sqlite3.connect('meu_banco.db') as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE usuarios SET facebook_token = NULL WHERE facebook_token = ?',
                (token,)
            )
            if cursor.rowcount == 0:
                return jsonify({'message': 'Token inválido ou já deslogado!'}), 404

            conn.commit()

        return jsonify({'message': 'Logout realizado com sucesso!'}), 200

    except Exception as e:
        print(f"Erro ao realizar logout: {e}")
        return jsonify({'message': 'Erro no servidor ao realizar logout!'}), 500

@app.route('/list-empresas', methods=['POST'])
def list_empresas():
    # Recebe o email do corpo da requisição
    data = request.get_json()
    email = data.get('email')
    
    if not email:
        return jsonify({"error": "Email não fornecido"}), 400

    # Conectar ao banco de dados
    conn = get_db_connection()

    # Procurar o usuário pelo email
    user_query = "SELECT id FROM usuarios WHERE email = ?"
    user = conn.execute(user_query, (email,)).fetchone()

    if not user:
        return jsonify({"error": "Usuário não encontrado"}), 404

    # Pegar o ID do usuário encontrado
    user_id = user['id']

    # Buscar as empresas associadas ao usuário
    empresas_query = "SELECT nome FROM empresas WHERE usuario_id = ?"
    empresas = conn.execute(empresas_query, (user_id,)).fetchall()

    # Fechar a conexão com o banco de dados
    conn.close()

    # Retornar os nomes das empresas
    if empresas:
        empresas_nomes = [empresa['nome'] for empresa in empresas]
        return jsonify({"empresas": empresas_nomes}), 200
    else:
        return jsonify({"message": "Nenhuma empresa encontrada para este usuário"}), 404
    
def salvar_token(email, token):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE empresas SET auth_token = ? WHERE usuario_id = (SELECT id FROM usuarios WHERE email = ?)", (token, email))
    conn.commit()
    conn.close()

@app.route('/registro-hotmart', methods=['POST'])
def registro_hotmart():
    data = request.json
    email = data.get('email')
    client_id = data.get('client_id')
    client_secret = data.get('client_secret')
    token = data.get('token')

    if not email or not client_id or not client_secret or not token:
        return jsonify({'error': 'Todos os campos são obrigatórios'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Buscar o ID do usuário com base no email
    cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({'error': 'Usuário não encontrado'}), 404

    user_id = user['id']

    # Buscar a empresa associada ao usuário
    cursor.execute("SELECT nome FROM empresas WHERE usuario_id = ?", (user_id,))
    empresa = cursor.fetchone()

    if not empresa:
        conn.close()
        return jsonify({'error': 'Empresa não encontrada'}), 404

    nome_empresa = empresa['nome']

    # Verificar se já existe um registro para essa empresa
    cursor.execute("SELECT * FROM empresas WHERE usuario_id = ?", (user_id,))
    empresa_existente = cursor.fetchone()

    if empresa_existente:
        # Atualizar os dados existentes
        cursor.execute("""
            UPDATE empresas
            SET client_id = ?, client_secret = ?, token = ?
            WHERE usuario_id = ?
        """, (client_id, client_secret, token, user_id))
    else:
        # Criar um novo registro
        cursor.execute("""
            INSERT INTO empresas (usuario_id, nome, client_id, client_secret, token)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, nome_empresa, client_id, client_secret, token))

    conn.commit()
    conn.close()

    return jsonify({'message': 'Configuração salva com sucesso!'})

@app.route('/api/history-sales', methods=['GET'])
def get_credentials_and_sales_history():
    email = request.args.get("email")
    empresa_nome = request.args.get("empresa")
    args = request.args.to_dict(flat=True)
    args.pop("email", None)  # Remover email dos argumentos
    args.pop("empresa", None)  # Remover empresa dos argumentos

    # Log da requisição recebida
    app.logger.debug(f"Requisição recebida - email: {email}, empresa: {empresa_nome}, args: {args}")

    # Validar parâmetros obrigatórios
    if not email or not empresa_nome:
        return jsonify({"error": "Email e empresa são obrigatórios."}), 400

    try:
        # Conectar ao banco de dados SQLite
        conn = sqlite3.connect("meu_banco.db")
        cursor = conn.cursor()

        # Pesquisar o email na tabela usuarios
        cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"error": "Usuário não encontrado."}), 404

        user_id = user[0]

        # Pesquisar credenciais na tabela empresas
        cursor.execute("SELECT client_id, client_secret, token FROM empresas WHERE usuario_id = ? AND nome = ?", (user_id, empresa_nome))
        empresa = cursor.fetchone()
        if not empresa:
            return jsonify({"error": "Empresa não encontrada para o usuário fornecido."}), 404

        client_id, client_secret, basic_token = empresa

        # Log das credenciais recuperadas
        app.logger.debug(f"Credenciais recuperadas - client_id: {client_id}, client_secret: {client_secret}, basic_token: {basic_token}")

        # Inicializar Hotmart Client
        hotmart = Hotmart(
            client_id=client_id,
            client_secret=client_secret,
            basic=basic_token,
            log_level=logging.INFO,
            sandbox=True
        )

        # Log dos argumentos passados para get_sales_history
        app.logger.debug(f"Chamando get_sales_history com argumentos: {args}")

        # Obter histórico de vendas com args dinâmicos
        sales_history = hotmart.get_sales_history(**args)
        return jsonify(sales_history)

    except sqlite3.Error as e:
        return jsonify({"error": "Erro ao acessar o banco de dados.", "details": str(e)}), 500

    except Exception as e:
        return jsonify({"error": "Erro inesperado.", "details": str(e)}), 500

    finally:
        if conn:
            conn.close()

@app.route('/api/summary-sales', methods=['GET'])
def get_credentials_and_summary():
    email = request.args.get("email")
    empresa_nome = request.args.get("empresa")
    args = request.args.to_dict(flat=True)
    args.pop("email", None)  # Remover email dos argumentos
    args.pop("empresa", None)  # Remover empresa dos argumentos

    # Log da requisição recebida
    app.logger.debug(f"Requisição recebida - email: {email}, empresa: {empresa_nome}, args: {args}")

    # Validar parâmetros obrigatórios
    if not email or not empresa_nome:
        return jsonify({"error": "Email e empresa são obrigatórios."}), 400

    try:
        # Conectar ao banco de dados SQLite
        conn = sqlite3.connect("meu_banco.db")
        cursor = conn.cursor()

        # Pesquisar o email na tabela usuarios
        cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"error": "Usuário não encontrado."}), 404

        user_id = user[0]

        # Pesquisar credenciais na tabela empresas
        cursor.execute("SELECT client_id, client_secret, token FROM empresas WHERE usuario_id = ? AND nome = ?", (user_id, empresa_nome))
        empresa = cursor.fetchone()
        if not empresa:
            return jsonify({"error": "Empresa não encontrada para o usuário fornecido."}), 404

        client_id, client_secret, basic_token = empresa

        # Log das credenciais recuperadas
        app.logger.debug(f"Credenciais recuperadas - client_id: {client_id}, client_secret: {client_secret}, basic_token: {basic_token}")

        # Inicializar Hotmart Client
        hotmart = Hotmart(
            client_id=client_id,
            client_secret=client_secret,
            basic=basic_token,
            log_level=logging.INFO,
            sandbox=True
        )

        # Log dos argumentos passados para get_sales_history
        app.logger.debug(f"Chamando get_sales_summary com argumentos: {args}")

        # Obter histórico de vendas com args dinâmicos
        sales_summary = hotmart.get_sales_summary(**args)
        return jsonify(sales_summary)

    except sqlite3.Error as e:
        return jsonify({"error": "Erro ao acessar o banco de dados.", "details": str(e)}), 500

    except Exception as e:
        return jsonify({"error": "Erro inesperado.", "details": str(e)}), 500

    finally:
        if conn:
            conn.close()

@app.route('/api/sales-price-details', methods=['GET'])
def get_credentials_and_price_details():
    email = request.args.get("email")
    empresa_nome = request.args.get("empresa")
    args = request.args.to_dict(flat=True)
    args.pop("email", None)  # Remover email dos argumentos
    args.pop("empresa", None)  # Remover empresa dos argumentos

    # Log da requisição recebida
    app.logger.debug(f"Requisição recebida - email: {email}, empresa: {empresa_nome}, args: {args}")

    # Validar parâmetros obrigatórios
    if not email or not empresa_nome:
        return jsonify({"error": "Email e empresa são obrigatórios."}), 400

    try:
        # Conectar ao banco de dados SQLite
        conn = sqlite3.connect("meu_banco.db")
        cursor = conn.cursor()

        # Pesquisar o email na tabela usuarios
        cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"error": "Usuário não encontrado."}), 404

        user_id = user[0]

        # Pesquisar credenciais na tabela empresas
        cursor.execute("SELECT client_id, client_secret, token FROM empresas WHERE usuario_id = ? AND nome = ?", (user_id, empresa_nome))
        empresa = cursor.fetchone()
        if not empresa:
            return jsonify({"error": "Empresa não encontrada para o usuário fornecido."}), 404

        client_id, client_secret, basic_token = empresa

        # Log das credenciais recuperadas
        app.logger.debug(f"Credenciais recuperadas - client_id: {client_id}, client_secret: {client_secret}, basic_token: {basic_token}")

        # Inicializar Hotmart Client
        hotmart = Hotmart(
            client_id=client_id,
            client_secret=client_secret,
            basic=basic_token,
            log_level=logging.INFO,
            sandbox=True
        )

        # Log dos argumentos passados para get_sales_history
        app.logger.debug(f"Chamando get_sales_price_details com argumentos: {args}")

        # Obter histórico de vendas com args dinâmicos
        sales_price = hotmart.get_sales_price_details(**args)
        return jsonify(sales_price)

    except sqlite3.Error as e:
        return jsonify({"error": "Erro ao acessar o banco de dados.", "details": str(e)}), 500

    except Exception as e:
        return jsonify({"error": "Erro inesperado.", "details": str(e)}), 500

    finally:
        if conn:
            conn.close()

@app.route('/api/users-sales', methods=['GET'])
def get_credentials_and_users_sales():
    email = request.args.get("email")
    empresa_nome = request.args.get("empresa")
    args = request.args.to_dict(flat=True)
    args.pop("email", None)  # Remover email dos argumentos
    args.pop("empresa", None)  # Remover empresa dos argumentos

    # Log da requisição recebida
    app.logger.debug(f"Requisição recebida - email: {email}, empresa: {empresa_nome}, args: {args}")

    # Validar parâmetros obrigatórios
    if not email or not empresa_nome:
        return jsonify({"error": "Email e empresa são obrigatórios."}), 400

    try:
        # Conectar ao banco de dados SQLite
        conn = sqlite3.connect("meu_banco.db")
        cursor = conn.cursor()

        # Pesquisar o email na tabela usuarios
        cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"error": "Usuário não encontrado."}), 404

        user_id = user[0]

        # Pesquisar credenciais na tabela empresas
        cursor.execute("SELECT client_id, client_secret, token FROM empresas WHERE usuario_id = ? AND nome = ?", (user_id, empresa_nome))
        empresa = cursor.fetchone()
        if not empresa:
            return jsonify({"error": "Empresa não encontrada para o usuário fornecido."}), 404

        client_id, client_secret, basic_token = empresa

        # Log das credenciais recuperadas
        app.logger.debug(f"Credenciais recuperadas - client_id: {client_id}, client_secret: {client_secret}, basic_token: {basic_token}")

        # Inicializar Hotmart Client
        hotmart = Hotmart(
            client_id=client_id,
            client_secret=client_secret,
            basic=basic_token,
            log_level=logging.INFO,
            sandbox=True
        )

        # Log dos argumentos passados para get_sales_history
        app.logger.debug(f"Chamando get_sales_users com argumentos: {args}")

        # Obter histórico de vendas com args dinâmicos
        sales_users = hotmart.get_sales_participants(**args)
        return jsonify(sales_users)

    except sqlite3.Error as e:
        return jsonify({"error": "Erro ao acessar o banco de dados.", "details": str(e)}), 500

    except Exception as e:
        return jsonify({"error": "Erro inesperado.", "details": str(e)}), 500

    finally:
        if conn:
            conn.close()

@app.route('/api/comissions-sales', methods=['GET'])
def get_credentials_and_comissions():
    email = request.args.get("email")
    empresa_nome = request.args.get("empresa")
    args = request.args.to_dict(flat=True)
    args.pop("email", None)  # Remover email dos argumentos
    args.pop("empresa", None)  # Remover empresa dos argumentos

    # Log da requisição recebida
    app.logger.debug(f"Requisição recebida - email: {email}, empresa: {empresa_nome}, args: {args}")

    # Validar parâmetros obrigatórios
    if not email or not empresa_nome:
        return jsonify({"error": "Email e empresa são obrigatórios."}), 400

    try:
        # Conectar ao banco de dados SQLite
        conn = sqlite3.connect("meu_banco.db")
        cursor = conn.cursor()

        # Pesquisar o email na tabela usuarios
        cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"error": "Usuário não encontrado."}), 404

        user_id = user[0]

        # Pesquisar credenciais na tabela empresas
        cursor.execute("SELECT client_id, client_secret, token FROM empresas WHERE usuario_id = ? AND nome = ?", (user_id, empresa_nome))
        empresa = cursor.fetchone()
        if not empresa:
            return jsonify({"error": "Empresa não encontrada para o usuário fornecido."}), 404

        client_id, client_secret, basic_token = empresa

        # Log das credenciais recuperadas
        app.logger.debug(f"Credenciais recuperadas - client_id: {client_id}, client_secret: {client_secret}, basic_token: {basic_token}")

        # Inicializar Hotmart Client
        hotmart = Hotmart(
            client_id=client_id,
            client_secret=client_secret,
            basic=basic_token,
            log_level=logging.INFO,
            sandbox=True
        )

        # Log dos argumentos passados para get_sales_history
        app.logger.debug(f"Chamando get_sales_comissions com argumentos: {args}")

        # Obter histórico de vendas com args dinâmicos
        sales_commisions = hotmart.get_sales_commissions(**args)
        return jsonify(sales_commisions)

    except sqlite3.Error as e:
        return jsonify({"error": "Erro ao acessar o banco de dados.", "details": str(e)}), 500

    except Exception as e:
        return jsonify({"error": "Erro inesperado.", "details": str(e)}), 500

    finally:
        if conn:
            conn.close()

@app.route('/facebook-login')
def facebook_login():
    """Rota para iniciar o processo de login do Facebook."""
    auth_url = (
        f'https://www.facebook.com/v21.0/dialog/oauth?'
        f'client_id={FACEBOOK_APP_ID}&'
        f'redirect_uri={FACEBOOK_REDIRECT_URI}&'
        f'scope=read_insights,ads_management,ads_read,business_management'
    )
    return redirect(auth_url)

@app.route('/callback')
def callback():
    """Recebe o código do Facebook, obtém o token e o salva no banco de dados corretamente."""
    print("🔄 Recebendo callback...")

    # Captura o código da URL
    code = request.args.get('code')
    if not code:
        print("❌ Erro: Código não encontrado na URL.")
        return "Código não encontrado na URL", 400

    # Faz a requisição para trocar o código pelo token
    token_url = f"https://graph.facebook.com/v21.0/oauth/access_token?" \
                f"client_id={FACEBOOK_APP_ID}&" \
                f"client_secret={FACEBOOK_APP_SECRET}&" \
                f"code={code}&" \
                f"redirect_uri={FACEBOOK_REDIRECT_URI}"
    
    print("🔍 Requisitando token do Facebook...")
    response = requests.get(token_url)
    
    if response.status_code != 200:
        print(f"❌ Erro na requisição do token. Resposta do Facebook: {response.text}")
        return "Erro ao obter o token de acesso", 500

    # Processa a resposta da API do Facebook
    response_json = response.json()
    access_token = response_json.get('access_token')

    if not access_token:
        print("❌ Erro: Token não foi retornado pelo Facebook.")
        return "Erro ao obter o token de acesso", 500

    print(f"✅ Token recebido com sucesso: {access_token[:10]}... (ocultado por segurança)")

    # Conectar ao banco de dados
    conn = sqlite3.connect("meu_banco.db")
    cursor = conn.cursor()

    # Buscar credenciais temporárias (email e empresa)
    print("🔍 Buscando credenciais temporárias no banco...")
    cursor.execute("SELECT email, empresa FROM temp_login_data LIMIT 1")
    temp_data = cursor.fetchone()

    if not temp_data:
        print("❌ Erro: Nenhum dado temporário encontrado.")
        conn.close()
        return "Erro: Nenhum dado temporário encontrado", 400

    email, empresa = temp_data
    print(f"✅ Credenciais encontradas - Email: {email}, Empresa: {empresa}")

    # Buscar o ID do usuário com base no email
    cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
    usuario_result = cursor.fetchone()

    if not usuario_result:
        print("❌ Erro: Usuário não encontrado na tabela 'usuarios'.")
        conn.close()
        return "Usuário não encontrado", 404

    usuario_id = usuario_result[0]
    print(f"✅ ID do usuário encontrado: {usuario_id}")

    # Verifica se a empresa já está cadastrada para esse usuário
    cursor.execute("SELECT id FROM empresas WHERE usuario_id = ? AND nome = ?", (usuario_id, empresa))
    empresa_result = cursor.fetchone()

    if empresa_result:
        # Se a empresa já existe, atualiza o token
        cursor.execute("UPDATE empresas SET auth_token = ? WHERE usuario_id = ? AND nome = ?", 
                       (access_token, usuario_id, empresa))
        print("🔄 Token atualizado com sucesso para a empresa existente.")
    else:
        # Se a empresa não existe, cria um novo registro
        cursor.execute("INSERT INTO empresas (usuario_id, nome, auth_token) VALUES (?, ?, ?)", 
                       (usuario_id, empresa, access_token))
        print("✅ Nova empresa cadastrada com o token.")

    # Salvar alterações no banco de dados
    conn.commit()

    # Remover os dados temporários
    cursor.execute("DELETE FROM temp_login_data WHERE email = ? AND empresa = ?", (email, empresa))
    conn.commit()
    print("🗑️ Dados temporários removidos com sucesso!")

    # Fechar conexão com o banco
    conn.close()

    # Armazena o token na sessão
    session['fb_token'] = access_token

    print("🚀 Redirecionando para o frontend...")
    return redirect("https://nakazawa.vercel.app/metricas")

@app.route('/logout-facebook', methods=['POST'])
def logout_facebook():
    data = request.json
    email = data.get("email")
    empresa = data.get("empresa")

    if not email or not empresa:
        return jsonify({"success": False, "message": "Email e empresa são obrigatórios."}), 400

    conn = sqlite3.connect("meu_banco.db")
    cursor = conn.cursor()

    try:
        # Obtém o ID do usuário pelo email
        cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
        usuario_id_result = cursor.fetchone()

        if not usuario_id_result:
            return jsonify({"success": False, "message": "Usuário não encontrado."}), 404

        usuario_id = usuario_id_result[0]

        # Verifica se a empresa está vinculada ao usuário
        cursor.execute("SELECT auth_token FROM empresas WHERE usuario_id = ? AND nome = ?", (usuario_id, empresa))
        result = cursor.fetchone()

        if result and result[0]:
            # Remove o token de autenticação da empresa vinculada ao usuário
            cursor.execute("UPDATE empresas SET auth_token = NULL WHERE usuario_id = ? AND nome = ?", (usuario_id, empresa))
            conn.commit()

            return jsonify({"success": True, "message": "Logout realizado com sucesso, token removido."})
        else:
            return jsonify({"success": False, "message": "Nenhum token encontrado para essa empresa."}), 404

    except Exception as e:
        return jsonify({"success": False, "message": f"Erro interno: {str(e)}"}), 500
    
    finally:
        conn.close()  # Certifica-se de que o banco será fechado corretamente           

@app.route('/check-facebook-login', methods=['POST'])
def check_facebook_login():
    data = request.json
    email = data.get("email")
    empresa = data.get("empresa")

    if not email or not empresa:
        return jsonify({"loggedIn": False, "message": "Email e empresa são obrigatórios."}), 400

    conn = sqlite3.connect("meu_banco.db")
    cursor = conn.cursor()

    try:
        # Insere as credenciais temporárias na tabela temp_login_data
        cursor.execute("INSERT INTO temp_login_data (email, empresa) VALUES (?, ?)", (email, empresa))
        conn.commit()

        # Obtém o ID do usuário pelo email
        cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
        usuario_id_result = cursor.fetchone()

        if not usuario_id_result:
            return jsonify({"loggedIn": False, "message": "Usuário não encontrado."}), 404

        usuario_id = usuario_id_result[0]

        # Obtém o token de autenticação da empresa vinculada ao usuário
        cursor.execute("SELECT auth_token FROM empresas WHERE usuario_id = ? AND nome = ?", (usuario_id, empresa))
        result = cursor.fetchone()

        if result and result[0]:
            auth_token = result[0]

            # Verifica o token no Facebook
            graph_url = f'https://graph.facebook.com/v21.0/me?fields=id&access_token={auth_token}'
            graph_response = requests.get(graph_url)

            if graph_response.status_code == 200:
                graph_data = graph_response.json()
                if 'id' in graph_data:
                    return jsonify({"loggedIn": True, "user_info": graph_data})
                else:
                    return jsonify({"loggedIn": False, "message": "Token inválido ou expirado. Faça login novamente."}), 401
            else:
                return jsonify({"loggedIn": False, "message": "Erro ao verificar o token no Facebook."}), 500
        else:
            return jsonify({"loggedIn": False, "message": "Usuário não logado. Por favor, faça login."}), 401

    except Exception as e:
        return jsonify({"loggedIn": False, "message": f"Erro interno: {str(e)}"}), 500

    finally:
        conn.close()

def obter_token(email, nome_empresa):
    try:
        conn = sqlite3.connect("meu_banco.db")
        cursor = conn.cursor()

        # Buscar o id do usuário com o email fornecido
        cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
        usuario_id = cursor.fetchone()

        if not usuario_id:
            print(f"[DEBUG] Usuário não encontrado: {email}")
            return None, "Usuário não encontrado."

        usuario_id = usuario_id[0]

        # Buscar a empresa pelo nome e usuário_id
        cursor.execute("SELECT id FROM empresas WHERE usuario_id = ? AND nome = ?", (usuario_id, nome_empresa))
        empresa_id = cursor.fetchone()

        if not empresa_id:
            print(f"[DEBUG] Empresa não encontrada para o usuário {email} com o nome {nome_empresa}")
            return None, "Empresa não encontrada."

        empresa_id = empresa_id[0]

        # Buscar o auth_token da empresa
        cursor.execute("SELECT auth_token FROM empresas WHERE id = ?", (empresa_id,))
        resultado = cursor.fetchone()

        conn.close()

        if not resultado or not resultado[0]:
            print(f"[DEBUG] Token não encontrado para a empresa {nome_empresa} do usuário {email}")
            return None, "Token não encontrado."

        print(f"[DEBUG] Token obtido: {resultado[0][:20]}...")  # Exibe os primeiros 20 caracteres
        return resultado[0], None
    except Exception as e:
        print(f"[ERROR] Erro no banco de dados ao buscar token: {str(e)}")
        return None, f"Erro no banco de dados: {str(e)}"

@app.route('/api/facebook-campanhas', methods=['GET'])
def get_facebook_campaigns():
    email = request.args.get('email')
    nome_empresa = request.args.get('nome_empresa')
    
    if not email:
        return jsonify({'error': 'Email é necessário'}), 400
    
    if not nome_empresa:
        return jsonify({'error': 'Nome da empresa é necessário'}), 400

    # Obter o token do banco de dados
    auth_token, erro = obter_token(email, nome_empresa)
    if not auth_token:
        return jsonify({'error': erro}), 404

    # Log para verificar o token
    print(f"[DEBUG] Token usado: {auth_token[:20]}...")  # Mostra os primeiros 20 caracteres

    # URL da API do Facebook
    url = f"https://graph.facebook.com/v21.0/me/adaccounts?fields=name&access_token={auth_token}"
    print(f"[DEBUG] URL chamada: {url}")

    try:
        # Fazer a requisição para o Facebook
        response = requests.get(url)
        print(f"[DEBUG] Status de resposta: {response.status_code}")
        print(f"[DEBUG] Resposta da API: {response.text}")

        # Se o status não for 200, exiba o erro retornado
        if response.status_code != 200:
            return jsonify({'error': f"Erro ao obter campanhas: {response.text}"}), 500

        # Processar a resposta JSON
        data = response.json()
        if 'data' not in data:
            return jsonify({'error': 'A resposta não contém campanhas'}), 500

        # Extrair e retornar as campanhas
        campaigns = [{"name": campaign["name"], "id": campaign["id"]} for campaign in data['data']]
        return jsonify(campaigns)

    except Exception as e:
        print(f"[ERROR] Erro ao fazer requisição para o Facebook: {e}")
        return jsonify({'error': 'Erro ao fazer requisição para o Facebook'}), 500

# Rota para buscar campanhas de uma conta de anúncios específica
@app.route('/api/facebook-anuncios', methods=['GET'])
def get_facebook_anuncios():
    email = request.args.get('email')
    nome_empresa = request.args.get('nome_empresa')
    ad_account_id = request.args.get('ad_account_id')  # ID da conta de anúncios obrigatório

    if not email:
        return jsonify({'error': 'Email é necessário'}), 400

    if not nome_empresa:
        return jsonify({'error': 'Nome da empresa é necessário'}), 400

    if not ad_account_id:
        return jsonify({'error': 'O ID da conta de anúncios (ad_account_id) é necessário'}), 400

    # Obter o token do banco de dados
    auth_token, erro = obter_token(email, nome_empresa)
    if not auth_token:
        return jsonify({'error': erro}), 404

    print(f"[DEBUG] Token usado: {auth_token[:20]}...")  # Mostra os primeiros 20 caracteres

    # URL para buscar campanhas da conta de anúncios
    url = f"https://graph.facebook.com/v21.0/{ad_account_id}/campaigns?fields=name,id&access_token={auth_token}"
    print(f"[DEBUG] URL chamada para campanhas: {url}")

    try:
        response = requests.get(url)
        print(f"[DEBUG] Status de resposta: {response.status_code}")
        print(f"[DEBUG] Resposta da API: {response.text}")

        if response.status_code != 200:
            return jsonify({'error': f"Erro ao obter campanhas: {response.text}"}), 500

        data = response.json()
        if 'data' not in data:
            return jsonify({'error': 'A resposta não contém campanhas'}), 500

        return jsonify(data['data'])

    except Exception as e:
        print(f"[ERROR] Erro ao fazer requisição para o Facebook: {e}")
        return jsonify({'error': 'Erro ao fazer requisição para o Facebook'}), 500

# Rota para buscar campanhas de uma conta de anúncios específica
@app.route('/api/facebook-adsets', methods=['GET'])
def get_facebook_adsets():
    email = request.args.get('email')
    nome_empresa = request.args.get('nome_empresa')
    ad_account_id = request.args.get('ad_account_id')  # ID da conta de anúncios obrigatório

    if not email:
        return jsonify({'error': 'Email é necessário'}), 400

    if not nome_empresa:
        return jsonify({'error': 'Nome da empresa é necessário'}), 400

    if not ad_account_id:
        return jsonify({'error': 'O ID da conta de anúncios (ad_account_id) é necessário'}), 400

    # Obter o token do banco de dados
    auth_token, erro = obter_token(email, nome_empresa)
    if not auth_token:
        return jsonify({'error': erro}), 404

    print(f"[DEBUG] Token usado: {auth_token[:20]}...")  # Mostra os primeiros 20 caracteres

    # URL para buscar campanhas da conta de anúncios
    url = f"https://graph.facebook.com/v21.0/{ad_account_id}/adsets?fields=name,id,status&access_token={auth_token}"
    print(f"[DEBUG] URL chamada para campanhas: {url}")

    try:
        response = requests.get(url)
        print(f"[DEBUG] Status de resposta: {response.status_code}")
        print(f"[DEBUG] Resposta da API: {response.text}")

        if response.status_code != 200:
            return jsonify({'error': f"Erro ao obter campanhas: {response.text}"}), 500

        data = response.json()
        if 'data' not in data:
            return jsonify({'error': 'A resposta não contém campanhas'}), 500

        return jsonify(data['data'])

    except Exception as e:
        print(f"[ERROR] Erro ao fazer requisição para o Facebook: {e}")
        return jsonify({'error': 'Erro ao fazer requisição para o Facebook'}), 500

# 2️⃣ Rota para obter previsões de frequência do Facebook
@app.route('/api/frequency-predictions', methods=['GET'])
def get_frequency_predictions():
    email = request.args.get('email')
    nome_empresa = request.args.get('nome_empresa')
    campaign_id = request.args.get('campaignId')
    fields = request.args.get('fields')
    
    if not email:
        return jsonify({'error': 'Email é necessário'}), 400
    
    if not nome_empresa:
        return jsonify({'error': 'Nome da empresa é necessário'}), 400

    if not campaign_id:
        return jsonify({'error': 'Campaign ID é necessário'}), 400

    if not fields:
        return jsonify({'error': 'Fields são necessários'}), 400

    # Obter o token do banco de dados
    auth_token, erro = obter_token(email, nome_empresa)
    if not auth_token:
        return jsonify({'error': erro}), 404

    # Construindo a URL da API do Facebook
    url = f"https://graph.facebook.com/v21.0/{campaign_id}/reachfrequencypredictions?fields={fields}&access_token={auth_token}"
    
    # Debug para verificar a URL montada
    print(f"[DEBUG] URL chamada: {url}")

    try:
        # Fazer a requisição para o Facebook
        response = requests.get(url)
        print(f"[DEBUG] Status de resposta: {response.status_code}")
        print(f"[DEBUG] Resposta da API: {response.text}")

        # Verificar se a resposta foi bem-sucedida
        if response.status_code != 200:
            return jsonify({'error': f"Erro ao obter previsões: {response.text}"}), 500

        # Retornar os dados da API do Facebook
        return jsonify(response.json())

    except Exception as e:
        print(f"[ERROR] Erro ao fazer requisição para o Facebook: {str(e)}")
        return jsonify({'error': f'Erro na requisição ao Facebook: {str(e)}'}), 500

# 3 Rota para obter previsões de frequência do Facebook
@app.route('/api/ads-account', methods=['GET'])
def get_ads_account():
    email = request.args.get('email')
    nome_empresa = request.args.get('nome_empresa')
    campaign_id = request.args.get('campaignId')
    fields = request.args.get('fields')
    
    if not email:
        return jsonify({'error': 'Email é necessário'}), 400
    
    if not nome_empresa:
        return jsonify({'error': 'Nome da empresa é necessário'}), 400

    if not campaign_id:
        return jsonify({'error': 'Campaign ID é necessário'}), 400

    if not fields:
        return jsonify({'error': 'Fields são necessários'}), 400

    # Obter o token do banco de dados
    auth_token, erro = obter_token(email, nome_empresa)
    if not auth_token:
        return jsonify({'error': erro}), 404

    # Construindo a URL da API do Facebook
    url = f"https://graph.facebook.com/v21.0/{campaign_id}/ads?fields={fields}&access_token={auth_token}"
    
    # Debug para verificar a URL montada
    print(f"[DEBUG] URL chamada: {url}")

    try:
        # Fazer a requisição para o Facebook
        response = requests.get(url)
        print(f"[DEBUG] Status de resposta: {response.status_code}")
        print(f"[DEBUG] Resposta da API: {response.text}")

        # Verificar se a resposta foi bem-sucedida
        if response.status_code != 200:
            return jsonify({'error': f"Erro ao obter previsões: {response.text}"}), 500

        # Retornar os dados da API do Facebook
        return jsonify(response.json())

    except Exception as e:
        print(f"[ERROR] Erro ao fazer requisição para o Facebook: {str(e)}")
        return jsonify({'error': f'Erro na requisição ao Facebook: {str(e)}'}), 500

# 4 Rota para obter previsões de frequência do Facebook
@app.route('/api/adset-details', methods=['GET'])
def get_adset_details():
    email = request.args.get('email')
    nome_empresa = request.args.get('nome_empresa')
    campaign_id = request.args.get('campaignId')
    fields = request.args.get('fields')
    
    if not email:
        return jsonify({'error': 'Email é necessário'}), 400
    
    if not nome_empresa:
        return jsonify({'error': 'Nome da empresa é necessário'}), 400

    if not campaign_id:
        return jsonify({'error': 'Campaign ID é necessário'}), 400

    if not fields:
        return jsonify({'error': 'Fields são necessários'}), 400

    # Obter o token do banco de dados
    auth_token, erro = obter_token(email, nome_empresa)
    if not auth_token:
        return jsonify({'error': erro}), 404

    # Construindo a URL da API do Facebook
    url = f"https://graph.facebook.com/v21.0/{campaign_id}/adsets?fields={fields}&access_token={auth_token}"
    
    # Debug para verificar a URL montada
    print(f"[DEBUG] URL chamada: {url}")

    try:
        # Fazer a requisição para o Facebook
        response = requests.get(url)
        print(f"[DEBUG] Status de resposta: {response.status_code}")
        print(f"[DEBUG] Resposta da API: {response.text}")

        # Verificar se a resposta foi bem-sucedida
        if response.status_code != 200:
            return jsonify({'error': f"Erro ao obter previsões: {response.text}"}), 500

        # Retornar os dados da API do Facebook
        return jsonify(response.json())

    except Exception as e:
        print(f"[ERROR] Erro ao fazer requisição para o Facebook: {str(e)}")
        return jsonify({'error': f'Erro na requisição ao Facebook: {str(e)}'}), 500
    
# 5 Rota para obter previsões de frequência do Facebook
@app.route('/api/advertisable-applications', methods=['GET'])
def get_advertisable_applications():
    email = request.args.get('email')
    nome_empresa = request.args.get('nome_empresa')
    campaign_id = request.args.get('campaignId')
    fields = request.args.get('fields')
    
    if not email:
        return jsonify({'error': 'Email é necessário'}), 400
    
    if not nome_empresa:
        return jsonify({'error': 'Nome da empresa é necessário'}), 400

    if not campaign_id:
        return jsonify({'error': 'Campaign ID é necessário'}), 400

    if not fields:
        return jsonify({'error': 'Fields são necessários'}), 400

    # Obter o token do banco de dados
    auth_token, erro = obter_token(email, nome_empresa)
    if not auth_token:
        return jsonify({'error': erro}), 404

    # Construindo a URL da API do Facebook
    url = f"https://graph.facebook.com/v21.0/{campaign_id}/advertisable_applications?fields={fields}&access_token={auth_token}"
    
    # Debug para verificar a URL montada
    print(f"[DEBUG] URL chamada: {url}")

    try:
        # Fazer a requisição para o Facebook
        response = requests.get(url)
        print(f"[DEBUG] Status de resposta: {response.status_code}")
        print(f"[DEBUG] Resposta da API: {response.text}")

        # Verificar se a resposta foi bem-sucedida
        if response.status_code != 200:
            return jsonify({'error': f"Erro ao obter previsões: {response.text}"}), 500

        # Retornar os dados da API do Facebook
        return jsonify(response.json())

    except Exception as e:
        print(f"[ERROR] Erro ao fazer requisição para o Facebook: {str(e)}")
        return jsonify({'error': f'Erro na requisição ao Facebook: {str(e)}'}), 500

# 6 Rota para obter previsões de frequência do Facebook
@app.route('/api/campaign-details', methods=['GET'])
def get_campaign_details():
    email = request.args.get('email')
    nome_empresa = request.args.get('nome_empresa')
    campaign_id = request.args.get('campaignId')
    fields = request.args.get('fields')
    
    if not email:
        return jsonify({'error': 'Email é necessário'}), 400
    
    if not nome_empresa:
        return jsonify({'error': 'Nome da empresa é necessário'}), 400

    if not campaign_id:
        return jsonify({'error': 'Campaign ID é necessário'}), 400

    if not fields:
        return jsonify({'error': 'Fields são necessários'}), 400

    # Obter o token do banco de dados
    auth_token, erro = obter_token(email, nome_empresa)
    if not auth_token:
        return jsonify({'error': erro}), 404

    # Construindo a URL da API do Facebook
    url = f"https://graph.facebook.com/v21.0/{campaign_id}/campaigns?fields={fields}&access_token={auth_token}"
    
    # Debug para verificar a URL montada
    print(f"[DEBUG] URL chamada: {url}")

    try:
        # Fazer a requisição para o Facebook
        response = requests.get(url)
        print(f"[DEBUG] Status de resposta: {response.status_code}")
        print(f"[DEBUG] Resposta da API: {response.text}")

        # Verificar se a resposta foi bem-sucedida
        if response.status_code != 200:
            return jsonify({'error': f"Erro ao obter previsões: {response.text}"}), 500

        # Retornar os dados da API do Facebook
        return jsonify(response.json())

    except Exception as e:
        print(f"[ERROR] Erro ao fazer requisição para o Facebook: {str(e)}")
        return jsonify({'error': f'Erro na requisição ao Facebook: {str(e)}'}), 500

# 6 Rota para obter previsões de frequência do Facebook
@app.route('/api/custom-conversion', methods=['GET'])
def get_custom_conversion():
    email = request.args.get('email')
    nome_empresa = request.args.get('nome_empresa')
    campaign_id = request.args.get('campaignId')
    fields = request.args.get('fields')
    
    if not email:
        return jsonify({'error': 'Email é necessário'}), 400
    
    if not nome_empresa:
        return jsonify({'error': 'Nome da empresa é necessário'}), 400

    if not campaign_id:
        return jsonify({'error': 'Campaign ID é necessário'}), 400

    if not fields:
        return jsonify({'error': 'Fields são necessários'}), 400

    # Obter o token do banco de dados
    auth_token, erro = obter_token(email, nome_empresa)
    if not auth_token:
        return jsonify({'error': erro}), 404

    # Construindo a URL da API do Facebook
    url = f"https://graph.facebook.com/v21.0/{campaign_id}/customconversions?{fields}&access_token={auth_token}"
    
    # Debug para verificar a URL montada
    print(f"[DEBUG] URL chamada: {url}")

    try:
        # Fazer a requisição para o Facebook
        response = requests.get(url)
        print(f"[DEBUG] Status de resposta: {response.status_code}")
        print(f"[DEBUG] Resposta da API: {response.text}")

        # Verificar se a resposta foi bem-sucedida
        if response.status_code != 200:
            return jsonify({'error': f"Erro ao obter previsões: {response.text}"}), 500

        # Retornar os dados da API do Facebook
        return jsonify(response.json())

    except Exception as e:
        print(f"[ERROR] Erro ao fazer requisição para o Facebook: {str(e)}")
        return jsonify({'error': f'Erro na requisição ao Facebook: {str(e)}'}), 500

# 7 Rota para obter previsões de frequência do Facebook
@app.route('/api/pixel-details', methods=['GET'])
def get_pixel_details():
    email = request.args.get('email')
    nome_empresa = request.args.get('nome_empresa')
    campaign_id = request.args.get('campaignId')
    fields = request.args.get('fields')
    
    if not email:
        return jsonify({'error': 'Email é necessário'}), 400
    
    if not nome_empresa:
        return jsonify({'error': 'Nome da empresa é necessário'}), 400

    if not campaign_id:
        return jsonify({'error': 'Campaign ID é necessário'}), 400

    if not fields:
        return jsonify({'error': 'Fields são necessários'}), 400

    # Obter o token do banco de dados
    auth_token, erro = obter_token(email, nome_empresa)
    if not auth_token:
        return jsonify({'error': erro}), 404

    # Construindo a URL da API do Facebook
    url = f"https://graph.facebook.com/v21.0/{campaign_id}/{fields}&access_token={auth_token}"
    
    # Debug para verificar a URL montada
    print(f"[DEBUG] URL chamada: {url}")

    try:
        # Fazer a requisição para o Facebook
        response = requests.get(url)
        print(f"[DEBUG] Status de resposta: {response.status_code}")
        print(f"[DEBUG] Resposta da API: {response.text}")

        # Verificar se a resposta foi bem-sucedida
        if response.status_code != 200:
            return jsonify({'error': f"Erro ao obter previsões: {response.text}"}), 500

        # Retornar os dados da API do Facebook
        return jsonify(response.json())

    except Exception as e:
        print(f"[ERROR] Erro ao fazer requisição para o Facebook: {str(e)}")
        return jsonify({'error': f'Erro na requisição ao Facebook: {str(e)}'}), 500

# 9 Rota para obter previsões de frequência do Facebook
@app.route('/api/targeting-categories', methods=['GET'])
def get_targeting_categories():
    email = request.args.get('email')
    nome_empresa = request.args.get('nome_empresa')
    campaign_id = request.args.get('campaignId')
    fields = request.args.get('fields')
    
    if not email:
        return jsonify({'error': 'Email é necessário'}), 400
    
    if not nome_empresa:
        return jsonify({'error': 'Nome da empresa é necessário'}), 400

    if not campaign_id:
        return jsonify({'error': 'Campaign ID é necessário'}), 400

    if not fields:
        return jsonify({'error': 'Fields são necessários'}), 400

    # Obter o token do banco de dados
    auth_token, erro = obter_token(email, nome_empresa)
    if not auth_token:
        return jsonify({'error': erro}), 404

    # Construindo a URL da API do Facebook
    url = f"https://graph.facebook.com/v21.0/{campaign_id}/{fields}&access_token={auth_token}"
    
    # Debug para verificar a URL montada
    print(f"[DEBUG] URL chamada: {url}")

    try:
        # Fazer a requisição para o Facebook
        response = requests.get(url)
        print(f"[DEBUG] Status de resposta: {response.status_code}")
        print(f"[DEBUG] Resposta da API: {response.text}")

        # Verificar se a resposta foi bem-sucedida
        if response.status_code != 200:
            return jsonify({'error': f"Erro ao obter previsões: {response.text}"}), 500

        # Retornar os dados da API do Facebook
        return jsonify(response.json())

    except Exception as e:
        print(f"[ERROR] Erro ao fazer requisição para o Facebook: {str(e)}")
        return jsonify({'error': f'Erro na requisição ao Facebook: {str(e)}'}), 500

@app.route('/api/campaign-groupfields', methods=['GET'])
def get_campaign_group_fields():
    email = request.args.get('email')
    nome_empresa = request.args.get('nome_empresa')
    anuncio = request.args.get('anuncio')  # Ajustado de campaignId para anuncio
    fields = request.args.get('fields')

    if not email:
        return jsonify({'error': 'Email é necessário'}), 400

    if not nome_empresa:
        return jsonify({'error': 'Nome da empresa é necessário'}), 400

    if not anuncio:  # Alterado de campaign_id para anuncio
        return jsonify({'error': 'Anuncio é necessário'}), 400

    if not fields:
        return jsonify({'error': 'Fields são necessários'}), 400

    # Obter o token do banco de dados
    auth_token, erro = obter_token(email, nome_empresa)
    if not auth_token:
        return jsonify({'error': erro}), 404

    # Construindo a URL da API do Facebook
    url = f"https://graph.facebook.com/v21.0/{anuncio}?fields={fields}&access_token={auth_token}"
    
    # Debug para verificar a URL montada
    print(f"[DEBUG] URL chamada: {url}")

    try:
        # Fazer a requisição para o Facebook
        response = requests.get(url)
        print(f"[DEBUG] Status de resposta: {response.status_code}")
        print(f"[DEBUG] Resposta da API: {response.text}")

        # Verificar se a resposta foi bem-sucedida
        if response.status_code != 200:
            return jsonify({'error': f"Erro ao obter dados: {response.text}"}), 500

        # Retornar os dados da API do Facebook
        return jsonify(response.json())

    except Exception as e:
        print(f"[ERROR] Erro ao fazer requisição para o Facebook: {str(e)}")
        return jsonify({'error': f'Erro na requisição ao Facebook: {str(e)}'}), 500

@app.route('/api/campaign-withfields', methods=['GET'])
def get_campaign_with_fields():
    email = request.args.get('email')
    nome_empresa = request.args.get('nome_empresa')
    anuncio = request.args.get('anuncio')  # Ajustado de campaignId para anuncio
    fields = request.args.get('fields')

    if not email:
        return jsonify({'error': 'Email é necessário'}), 400

    if not nome_empresa:
        return jsonify({'error': 'Nome da empresa é necessário'}), 400

    if not anuncio:  # Alterado de campaign_id para anuncio
        return jsonify({'error': 'Anuncio é necessário'}), 400

    if not fields:
        return jsonify({'error': 'Fields são necessários'}), 400

    # Obter o token do banco de dados
    auth_token, erro = obter_token(email, nome_empresa)
    if not auth_token:
        return jsonify({'error': erro}), 404

    # Construindo a URL da API do Facebook
    url = f"https://graph.facebook.com/v21.0/{anuncio}?fields={fields}&access_token={auth_token}"
    
    # Debug para verificar a URL montada
    print(f"[DEBUG] URL chamada: {url}")

    try:
        # Fazer a requisição para o Facebook
        response = requests.get(url)
        print(f"[DEBUG] Status de resposta: {response.status_code}")
        print(f"[DEBUG] Resposta da API: {response.text}")

        # Verificar se a resposta foi bem-sucedida
        if response.status_code != 200:
            return jsonify({'error': f"Erro ao obter dados: {response.text}"}), 500

        # Retornar os dados da API do Facebook
        return jsonify(response.json())

    except Exception as e:
        print(f"[ERROR] Erro ao fazer requisição para o Facebook: {str(e)}")
        return jsonify({'error': f'Erro na requisição ao Facebook: {str(e)}'}), 500

# Rota para buscar campanhas de uma conta de anúncios específica
@app.route('/api/pixel-id', methods=['GET'])
def get_pixel_id():
    email = request.args.get('email')
    nome_empresa = request.args.get('nome_empresa')
    ad_account_id = request.args.get('ad_account_id')  # ID da conta de anúncios obrigatório

    if not email:
        return jsonify({'error': 'Email é necessário'}), 400

    if not nome_empresa:
        return jsonify({'error': 'Nome da empresa é necessário'}), 400

    if not ad_account_id:
        return jsonify({'error': 'O ID da conta de anúncios (ad_account_id) é necessário'}), 400

    # Obter o token do banco de dados
    auth_token, erro = obter_token(email, nome_empresa)
    if not auth_token:
        return jsonify({'error': erro}), 404

    print(f"[DEBUG] Token usado: {auth_token[:20]}...")  # Mostra os primeiros 20 caracteres

    # URL para buscar campanhas da conta de anúncios
    url = f"https://graph.facebook.com/v21.0/{ad_account_id}/adspixels?access_token={auth_token}"
    print(f"[DEBUG] URL chamada para campanhas: {url}")

    try:
        response = requests.get(url)
        print(f"[DEBUG] Status de resposta: {response.status_code}")
        print(f"[DEBUG] Resposta da API: {response.text}")

        if response.status_code != 200:
            return jsonify({'error': f"Erro ao obter campanhas: {response.text}"}), 500

        data = response.json()
        if 'data' not in data:
            return jsonify({'error': 'A resposta não contém campanhas'}), 500

        return jsonify(data['data'])

    except Exception as e:
        print(f"[ERROR] Erro ao fazer requisição para o Facebook: {e}")
        return jsonify({'error': 'Erro ao fazer requisição para o Facebook'}), 500

@app.route('/api/pixelidstats', methods=['GET'])
def get_stats_pixelid():
    email = request.args.get('email')
    nome_empresa = request.args.get('nome_empresa')
    pixelid = request.args.get('pixelid')

    if not email:
        return jsonify({'error': 'Email é necessário'}), 400

    if not nome_empresa:
        return jsonify({'error': 'Nome da empresa é necessário'}), 400

    if not pixelid:  # Alterado de campaign_id para anuncio
        return jsonify({'error': 'Pixel Id é necessário'}), 400

    # Obter o token do banco de dados
    auth_token, erro = obter_token(email, nome_empresa)
    if not auth_token:
        return jsonify({'error': erro}), 404

    # Construindo a URL da API do Facebook
    url = f"https://graph.facebook.com/v21.0/{pixelid}/stats&access_token={auth_token}"
    
    # Debug para verificar a URL montada
    print(f"[DEBUG] URL chamada: {url}")

    try:
        # Fazer a requisição para o Facebook
        response = requests.get(url)
        print(f"[DEBUG] Status de resposta: {response.status_code}")
        print(f"[DEBUG] Resposta da API: {response.text}")

        # Verificar se a resposta foi bem-sucedida
        if response.status_code != 200:
            return jsonify({'error': f"Erro ao obter dados: {response.text}"}), 500

        # Retornar os dados da API do Facebook
        return jsonify(response.json())

    except Exception as e:
        print(f"[ERROR] Erro ao fazer requisição para o Facebook: {str(e)}")
        return jsonify({'error': f'Erro na requisição ao Facebook: {str(e)}'}), 500
    
@app.route('/api/adsetfieldsconfig', methods=['GET'])
def get_adset_fieldsconfig():
    email = request.args.get('email')
    nome_empresa = request.args.get('nome_empresa')
    anuncio = request.args.get('anuncio')
    fields = request.args.get('fields')

    if not email:
        return jsonify({'error': 'Email é necessário'}), 400

    if not nome_empresa:
        return jsonify({'error': 'Nome da empresa é necessário'}), 400

    if not anuncio:  # Alterado de campaign_id para anuncio
        return jsonify({'error': 'Id é necessário'}), 400
    
    if not fields:
        return jsonify({'error': 'parâmetros é necessário'})

    # Obter o token do banco de dados
    auth_token, erro = obter_token(email, nome_empresa)
    if not auth_token:
        return jsonify({'error': erro}), 404

    # Construindo a URL da API do Facebook
    url = f"https://graph.facebook.com/v21.0/{anuncio}?fields={fields}&access_token={auth_token}"
    
    # Debug para verificar a URL montada
    print(f"[DEBUG] URL chamada: {url}")

    try:
        # Fazer a requisição para o Facebook
        response = requests.get(url)
        print(f"[DEBUG] Status de resposta: {response.status_code}")
        print(f"[DEBUG] Resposta da API: {response.text}")

        # Verificar se a resposta foi bem-sucedida
        if response.status_code != 200:
            return jsonify({'error': f"Erro ao obter dados: {response.text}"}), 500

        # Retornar os dados da API do Facebook
        return jsonify(response.json())

    except Exception as e:
        print(f"[ERROR] Erro ao fazer requisição para o Facebook: {str(e)}")
        return jsonify({'error': f'Erro na requisição ao Facebook: {str(e)}'}), 500

@app.route('/api/insightsads', methods=['GET'])
def get_insights_ads():
    email = request.args.get('email')
    nome_empresa = request.args.get('nome_empresa')
    fields = request.args.get('fields')

    if not email:
        return jsonify({'error': 'Email é necessário'}), 400

    if not nome_empresa:
        return jsonify({'error': 'Nome da empresa é necessário'}), 400
    
    if not fields:
        return jsonify({'error': 'parâmetros é necessário'})

    # Obter o token do banco de dados
    auth_token, erro = obter_token(email, nome_empresa)
    if not auth_token:
        return jsonify({'error': erro}), 404

    # Construindo a URL da API do Facebook
    url = f"https://graph.facebook.com/v21.0/insights?{fields}&access_token={auth_token}"
    
    # Debug para verificar a URL montada
    print(f"[DEBUG] URL chamada: {url}")

    try:
        # Fazer a requisição para o Facebook
        response = requests.get(url)
        print(f"[DEBUG] Status de resposta: {response.status_code}")
        print(f"[DEBUG] Resposta da API: {response.text}")

        # Verificar se a resposta foi bem-sucedida
        if response.status_code != 200:
            return jsonify({'error': f"Erro ao obter dados: {response.text}"}), 500

        # Retornar os dados da API do Facebook
        return jsonify(response.json())

    except Exception as e:
        print(f"[ERROR] Erro ao fazer requisição para o Facebook: {str(e)}")
        return jsonify({'error': f'Erro na requisição ao Facebook: {str(e)}'}), 500

@app.route('/api/report-insights', methods=['GET'])
def get_report_insights():
    email = request.args.get('email')
    nome_empresa = request.args.get('nome_empresa')
    campaignId = request.args.get('campaignId')
    time_increment = request.args.get('time_increment')
    spend = request.args.get('spend')
    since = request.args.get('since')
    until = request.args.get('until')
    limit = request.args.get('limit')

    if not email:
        return jsonify({'error': 'Email é necessário'}), 400

    if not nome_empresa:
        return jsonify({'error': 'Nome da empresa é necessário'}), 400
    
    if not campaignId:
        return jsonify({'error': 'Campanha é necessária'}), 400
    
    if not time_increment:
        return jsonify({'error': 'time_increment é necessário'}), 400
    
    if not spend:
        return jsonify({'error': 'spend é necessário'}), 400
    
    if not since:
        return jsonify({'error': 'since é necessário'}), 400
    
    if not until:
        return jsonify({'error': 'until é necessário'}), 400
    
    if not limit:
        return jsonify({'error': 'limit é necessário'}), 400

    # Obter o token do banco de dados
    auth_token, erro = obter_token(email, nome_empresa)
    if not auth_token:
        return jsonify({'error': erro}), 404

    # Construindo a URL da API do Facebook
    url = (
        f"https://graph.facebook.com/v21.0/{campaignId}/insights"
        f"?time_range={{\"since\":\"{since}\",\"until\":\"{until}\"}}"
        f"&limit={limit}"
        f"&fields=spend,account_currency"
        f"&time_increment={time_increment}"
        f"&format=json"
        f"&access_token={auth_token}"
    )
    
    # Debug para verificar a URL montada
    print(f"[DEBUG] URL chamada: {url}")

    try:
        # Fazer a requisição para o Facebook
        response = requests.get(url)
        print(f"[DEBUG] Status de resposta: {response.status_code}")
        print(f"[DEBUG] Resposta da API: {response.text}")

        # Verificar se a resposta foi bem-sucedida
        if response.status_code != 200:
            return jsonify({'error': f"Erro ao obter dados: {response.text}"}), 500

        # Retornar os dados da API do Facebook
        return jsonify(response.json())

    except Exception as e:
        print(f"[ERROR] Erro ao fazer requisição para o Facebook: {str(e)}")
        return jsonify({'error': f'Erro na requisição ao Facebook: {str(e)}'}), 500

if __name__ == '__main__':
    # Estabelecendo o URL do redirect dinamicamente com ngrok
    FACEBOOK_REDIRECT_URI = ngrok.connect(5000).public_url + '/callback'
    print(f"URL de redirecionamento do Facebook configurado: {FACEBOOK_REDIRECT_URI}")
    
    # Inicializa o Flask
    app.run(host="0.0.0.0", debug=True, use_reloader=False)
