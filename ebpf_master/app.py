from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import requests
import psycopg2
from functools import wraps
import bcrypt
import socket
from jsonschema import validate, ValidationError

# Definir el JSON Schema
schema = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "properties": {
        "ip_source": {
            "type": "string",
            "format": "ipv4"
        },
        "port_dst": {
            "type": "integer",
            "minimum": 1,
            "maximum": 65535
        },
        "proto": {
            "type": "string",
            "enum": ["tcp", "udp", "icmp", "all"]
        }
    },
    "additionalProperties": False
}

schema_del = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": ["block", "allow"]
        },
        "ip_source": {
            "type": "string",
            "format": "ipv4"
        },
        "port_dst": {
            "type": "integer",
            "minimum": 1,
            "maximum": 65535
        },
        "proto": {
            "type": "string",
            "enum": ["tcp", "udp", "icmp", "all"]
        }
    },
    "additionalProperties": False
}

app = Flask(__name__)
app.secret_key = 'super_secret_key'

# Configuración de la base de datos
DB_CONFIG = {
    'dbname': 'firewall_users',
    'user': 'postgres',
    'password': 'postgres',
    'host': 'localhost',
    'port': '5432'
}

# Dirección de la API de reglas (modificar según sea necesario)
API_BASE_URL = "https://192.168.66.160:5027"

# Función para obtener la conexión a la base de datos
def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

# Decorador para proteger rutas
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# Ruta para el formulario de login
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return render_template('login.html', error="Faltan credenciales")

        try:
            conn = get_db_connection()
            cur = conn.cursor()

            # Consultar la base de datos para obtener el hash almacenado
            cur.execute("SELECT password FROM users WHERE username = %s", (username,))
            result = cur.fetchone()

            if result is not None:
                stored_password = result[0]
                if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                       print("OK")
                       #session['user_id'] = user_id  # Set user ID in session (assuming you have a user_id retrieved)
                       print("Redirecting to index...")
                       return redirect(url_for('index2'))
            else:
                return render_template('login.html', error="Usuario o contraseña incorrectos")

        except Exception as e:
            return render_template('login.html', error=f"Error: {str(e)}")
        finally:
            if conn:
                conn.close()

    # Si es una petición GET, renderizar el formulario de login
    return render_template('login.html')

# Ruta para cerrar sesión
@app.route('/logout', methods=['GET'])
#@login_required
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login_page'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login_ok')
#@login_required
def index2():
    return render_template('index.html')

@app.route('/list_rules', methods=['GET'])
#@login_required
def list_rules():
    try:
        # Llamada al endpoint de la API
        response = requests.get(f"{API_BASE_URL}/list_rules", verify='cert_back.pem')
        rules = response.json()
        return jsonify(rules)  # Devuelve las reglas en formato JSON
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/add_rule', methods=['POST'])
#@login_required
def add_rule():
    try:
        # Recibir datos del formulario
        data = request.get_json()
        action = data.get("action")  # Puede ser "block" o "allow"
        ip_source = data.get("ip_source")
        port_dst = data.get("port_dst")
        proto = data.get("proto")  # Protocolo opcional

        # Validar acción
        if action not in ["block", "allow"]:
            return jsonify({"error": "Acción inválida. Use 'block' o 'allow'"}), 400

        # Validar datos opcionales
        if port_dst:
            try:
                port_dst = int(port_dst)  # Convertir el puerto a un entero si se proporciona
            except ValueError:
                return jsonify({"error": "El puerto debe ser un número entero"}), 400

        if proto:
            valid_protos = ["tcp", "udp", "icmp"]
            if proto.lower() not in valid_protos:
                return jsonify({"error": f"Protocolo inválido. Use uno de {valid_protos}"}), 400

        # Seleccionar el endpoint correcto
        endpoint = "/add_rule_block" if action == "block" else "/add_rule_pass"

        # Construir el payload dinámicamente según los valores presentes
        payload = {key: value for key, value in {
            "ip_source": ip_source,
            "port_dst": port_dst,
            "proto": proto.lower() if proto else None
        }.items() if value is not None}

        try:
            validate(instance=payload, schema=schema)
        except ValidationError as e:
            print("Error de validación:", e.message)
            # Manejar el error, por ejemplo, abortar la solicitud
        else:
            # Enviar la solicitud POST si la validación es exitosa
            response = requests.post(f"{API_BASE_URL}{endpoint}", json=payload, verify='cert_back.pem')
        # Devolver la respuesta de la API

        return jsonify(response.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/delete_rule', methods=['POST'])
#@login_required
def delete_rule():
    try:
        # Obtener los datos enviados en el cuerpo de la solicitud
        data = request.get_json()
        action = data.get("action")  # "block" o "allow"
        ip_source = data.get("ip_source")
        port_dst = data.get("port_dst")
        proto = data.get("proto")  # Puede ser opcional

        # Validar acción
        if action not in ["block", "allow"]:
            return jsonify({"error": "Acción inválida. Use 'block' o 'allow'"}), 400

        # Construir el payload dinámicamente según los valores presentes
        payload = {key: value for key, value in {
            "action": action,  # Se incluye la acción en el payload
            "ip_source": ip_source,
            "port_dst": port_dst,
            "proto": proto.lower() if proto else None
        }.items() if value is not None}

        try:
            validate(instance=payload, schema=schema_del)
        except ValidationError as e:
            print("Error de validación:", e.message)
            # Manejar el error, por ejemplo, abortar la solicitud
        else:
            # Registrar el payload enviado
            print(f"Enviando payload a {API_BASE_URL}/delete_rule: {payload}")
            # Enviar la solicitud POST si la validación es exitosa
            response = requests.post(f"{API_BASE_URL}/delete_rule", json=payload, verify='cert_back.pem')

        # Devolver la respuesta de la API

        # Hacer la solicitud a la API de reglas

        # Manejar respuesta del backend
        try:
            response_data = response.json()  # Intentar parsear la respuesta JSON
        except ValueError:
            # Si no es JSON, devolver el texto plano del error
            return jsonify({"error": f"Error en el backend: {response.text}"}), response.status_code

        # Si la respuesta es exitosa, retornar el mensaje del backend
        if response.status_code == 200:
            return jsonify({"message": response_data.get("message", "Regla eliminada correctamente")})
        else:
            # Si hay un error, retornar el mensaje del backend
            return jsonify({"error": response_data.get("error", "Error desconocido")}), response.status_code

    except Exception as e:
        # Registrar errores en la aplicación
        print(f"Error en /delete_rule: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/get_agent_hostname', methods=['GET'])
def get_agent_hostname():
    try:
        hostname = socket.gethostname()  # Obtiene el hostname del sistema
        return jsonify({"hostname": hostname}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5028, ssl_context=('cert_front.pem', 'key_front.pem'))
