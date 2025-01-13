import bcrypt
import psycopg2
import argparse

# Configuración de la base de datos
DB_CONFIG = {
    'dbname': 'firewall_users',
    'user': 'postgres',
    'password': 'postgres',
    'host': 'localhost',
    'port': '5432'
}

def hash_password(password):
    """
    Genera un hash seguro para la contraseña proporcionada.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def insert_user(username, password):
    """
    Inserta un usuario en la base de datos con su contraseña hasheada.
    """
    try:
        # Conexión a la base de datos
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        # Hashear la contraseña
        hashed_password = hash_password(password)

        # Insertar usuario en la base de datos
        cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
        conn.commit()

        print(f"Usuario '{username}' insertado correctamente.")
    except Exception as e:
        print(f"Error al insertar usuario: {e}")
    finally:
        if conn:
            cur.close()
            conn.close()

if __name__ == "__main__":
    # Configuración del argumento de línea de comandos
    parser = argparse.ArgumentParser(description="Añadir un usuario con contraseña hasheada a la base de datos.")
    parser.add_argument("username", help="Nombre del usuario a añadir.")
    parser.add_argument("password", help="Contraseña del usuario.")

    # Parsear argumentos
    args = parser.parse_args()

    # Llamar a la función para insertar el usuario
    insert_user(args.username, args.password)
