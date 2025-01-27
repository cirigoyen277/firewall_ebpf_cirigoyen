from flask import Flask, request, jsonify
from bcc import BPF
import socket
import struct
import ctypes
import signal
import sys
import os
import psycopg2

app = Flask(__name__)

INTERFACE = "enp6s18"

# Programa eBPF
bpf_program = """
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>


struct rule_key_proto {
    u8 proto;
};
struct rule_key_ipsrc {
    u32 ip_src;
};
struct rule_key_ipsrc_proto_portdst {
    u8 proto;
    u32 ip_src;
    u16 port_dst;
};
BPF_HASH(allowed_rules1, struct rule_key_proto, u32);
BPF_HASH(allowed_rules2, struct rule_key_ipsrc, u32);
BPF_HASH(allowed_rules3, struct rule_key_ipsrc_proto_portdst, u32);
BPF_HASH(blocked_rules1, struct rule_key_proto, u32);
BPF_HASH(blocked_rules2, struct rule_key_ipsrc, u32);
BPF_HASH(blocked_rules3, struct rule_key_ipsrc_proto_portdst, u32);

int block_packet(struct xdp_md *ctx) {

    //////// EVITAR ACCESOS INVALIDOS EN MEMORIA //////////
    // Obtenemos los límites de los datos del paquete para evitar accesos inválidos.
    void *data = (void *)(long)ctx->data; // Inicio del paquete
    void *data_end = (void *)(long)ctx->data_end; // Fin del paquete
    // Verificar si el paquete tiene al menos la cabecera Ethernet completa
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS; // Si no, pasamos el paquete (no se procesa más)
    // Verificar si el paquete tiene un protocolo IP
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS; // Si no es IP, pasamos el paquete
    // Verificar si el paquete tiene al menos la cabecera IP completa
    struct iphdr *ip = data + sizeof(struct ethhdr); // Cabecera IP comienza después de Ethernet
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS; // Si no, pasamos el paquete
    // Verificar si el protocolo es TCP o UDP
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_ICMP)
        return XDP_PASS; // Si no es TCP o UDP, pasamos el paquete
    // Verificar si el paquete tiene al menos la cabecera TCP/UDP completa
    struct tcphdr *tcp = (void *)ip + sizeof(struct iphdr); // Cabecera TCP/UDP después de IP
    if ((void*)(tcp + 1) > data_end)
        return XDP_PASS; // Si no, pasamos el paquete

    // Crear una key para buscar en la tabla de reglas bloqueadas o permitidas
    struct rule_key_proto key1 = {};
    key1.proto = ip->protocol;

    struct rule_key_ipsrc key2 = {};
    key2.ip_src = ip->saddr;

    struct rule_key_ipsrc_proto_portdst key3 = {};
    key3.proto = ip->protocol;
    key3.ip_src = ip->saddr;
    key3.port_dst = tcp->dest;

    //////// CHECK WHITELIST ////////
    u32 *allow_value1 = allowed_rules1.lookup(&key1);
    if (allow_value1) {
        return XDP_PASS; // Si está en la whitelist, permite el tráfico
    }

    u32 *allow_value2 = allowed_rules2.lookup(&key2);
    if (allow_value2) {
        return XDP_PASS; // Si está en la whitelist, permite el tráfico
    }

    u32 *allow_value3 = allowed_rules3.lookup(&key3);
    if (allow_value3) {
        return XDP_PASS; // Si está en la whitelist, permite el tráfico
    }

    //////// CHECK BLACKLIST ////////
    u32 *block_value1 = blocked_rules1.lookup(&key1);
    if (block_value1) {
        return XDP_DROP; // Si está en la darklist, bloquea el tráfico
    }

    u32 *block_value2 = blocked_rules2.lookup(&key2);
    if (block_value2) {
        return XDP_DROP; // Si está en la darklist, bloquea el tráfico
    }

    u32 *block_value3 = blocked_rules3.lookup(&key3);
    if (block_value3) {
        return XDP_DROP; // Si está en la darklist, bloquea el tráfico
    }

    // Por defecto, se bloquea el paso
    return XDP_DROP;

    bpf_trace_printk("Paquete analizado: src IP %x, dst port %d\\n", ip->saddr, tcp->dest);
}
"""

# Inicializar BPF
b = BPF(text=bpf_program)
fn = b.load_func("block_packet", BPF.XDP)
b.attach_xdp(INTERFACE, fn)

class Key(ctypes.Structure):
    _fields_ = [
        ("proto", ctypes.c_uint8),      # Protocolo (u8)
        ("ip_src", ctypes.c_uint32),   # IP de origen (u32)
        ("port_dst", ctypes.c_uint16)  # Puerto de destino (u16)
    ]

# Mapa de reglas bloqueadas
blocked_rules1 = b.get_table("blocked_rules1")
blocked_rules2 = b.get_table("blocked_rules2")
blocked_rules3 = b.get_table("blocked_rules3")
blocked_rules3.Key = Key

# Mapa de reglas permitidas
allowed_rules1 = b.get_table("allowed_rules1")
allowed_rules2 = b.get_table("allowed_rules2")
allowed_rules3 = b.get_table("allowed_rules3")
allowed_rules3.Key = Key

# Función para limpiar el programa eBPF al salir
def cleanup(sig, frame):
    print("\nDesasociando el programa eBPF de la interfaz...")
    b.remove_xdp(INTERFACE, 0)
    print("Programa desasociado. Saliendo.")
    sys.exit(0)

# Registrar la función cleanup para las señales SIGINT y SIGTERM
signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# Convertir una dirección IP en formato string a un número de 32 bits (u32) con inversión de bytes
def ip_to_u32_inverted(ip_str):
    ip_bytes = socket.inet_aton(ip_str)  # Convierte IP a bytes
    ip_inverted = ip_bytes[::-1]  # Invierte los bytes
    return struct.unpack("!I", ip_inverted)[0]  # Convierte los bytes invertidos a u32

PROTO_MAP = {
    "tcp": 6,
    "udp": 17,
    "icmp": 1
}

# Leer las direcciones IP de la base de datos y exportarlas a un archivo de texto
def generar_whitelist_sip():
    conexion = psycopg2.connect(
        host="localhost",       # Ejemplo: "localhost"
        database="sip_whitelist",     # Nombre de la base de datos
        user="postgres",    # Usuario de la base de datos
        password="postgres" # Contraseña del usuario
    )
    # Consulta para obtener las direcciones IP
    consulta = "SELECT host(ip_address) FROM direcciones_ip;"
    # Ruta del archivo de texto
    ruta_archivo = "whitelist_sip.txt"
    try:
        # Crear un cursor para ejecutar la consulta
        with conexion.cursor() as cursor:
            cursor.execute(consulta)
            direcciones = cursor.fetchall()  # Obtener todas las filas

            # Abrir el archivo en modo de escritura
            with open(ruta_archivo, 'w') as archivo:
                for direccion in direcciones:
                    archivo.write(direccion[0] + "\n")  # Escribir cada IP en una línea
        print(f"Direcciones IP exportadas a {ruta_archivo} exitosamente.")
    except Exception as e:
        print("Ocurrió un error:", e)
    finally:
        conexion.close()  # Cerrar la conexión a la base de datos

# Configuración de reglas predeterminadas
default_allowed_rules = [
    {"proto": "udp", "ip_source": "100.100.100.100",  "port_dst": 22},
]

generar_whitelist_sip()
whitelist_sip_file = "whitelist_sip.txt"

if os.path.exists(whitelist_sip_file):
    with open(whitelist_sip_file, "r") as file:
        for line in file:
            ip = line.strip()  # Elimina espacios y saltos de línea
            if ip:  # Si la línea no está vacía
                default_allowed_rules.append({"proto": "udp", "ip_source": ip, "port_dst": 5060})
else:
    print(f"El archivo '{whitelist_sip_file}' no existe. No se cargaron reglas adicionales.")

# Cargar reglas predeterminadas en el mapa allowed_rules
for rule in default_allowed_rules:
    ip_src = ip_to_u32_inverted(rule["ip_source"])
    port_dst = ctypes.c_uint16(socket.htons(rule["port_dst"]))
    proto = ctypes.c_uint8(PROTO_MAP[rule["proto"].lower()])
    key = allowed_rules3.Key(proto, ip_src, port_dst)
    allowed_rules3[key] = ctypes.c_uint32(1)

whitelist_all_file = "whitelist_all.txt"
if os.path.exists(whitelist_all_file):
    with open(whitelist_all_file, "r") as file:
        for line in file:
            ip = line.strip()  # Elimina espacios y saltos de línea
            if ip:  # Si la línea no está vacía
                ip_src_u32 = ip_to_u32_inverted(ip)
                key = ctypes.c_uint32(ip_src_u32)
                allowed_rules2[key] = ctypes.c_uint32(1)
else:
    print(f"El archivo '{whitelist_all_file}' no existe. No se cargaron reglas adicionales.")

# Regla por defecto para permitir todo el ICMP
key = ctypes.c_uint8(PROTO_MAP["icmp"])
allowed_rules1[key] = ctypes.c_uint32(1)


############# API FLASK ##############

# Endpoint para añadir regla
@app.route('/add_rule_block', methods=['POST'])
def add_rule_block():
    data = request.get_json()
    ip_src = data.get("ip_source")
    port_dst = data.get("port_dst")
    proto_str = data.get("proto", "").lower()  # Protocolo en minúscula

    try:
        # Caso 1: Solo protocolo especificado
        if proto_str and not ip_src and not port_dst:
            if proto_str not in PROTO_MAP:
                return jsonify({"error": "Protocolo inválido"}), 400
            key = ctypes.c_uint8(PROTO_MAP[proto_str])
            blocked_rules1[key] = ctypes.c_uint32(1)
            return jsonify({"message": f"Regla añadida: bloquear protocolo {proto_str}"}), 200

        # Caso 2: Solo IP fuente especificada
        elif ip_src and not port_dst and not proto_str:
            ip_src_u32 = ip_to_u32_inverted(ip_src)
            key = ctypes.c_uint32(ip_src_u32)
            blocked_rules2[key] = ctypes.c_uint32(1)
            return jsonify({"message": f"Regla añadida: bloquear IP de origen {ip_src}"}), 200

        # Caso 3: IP, puerto y protocolo especificados (original)
        elif ip_src and port_dst and proto_str:
            if proto_str not in PROTO_MAP:
                return jsonify({"error": "Protocolo inválido"}), 400
            key = blocked_rules3.Key(
                ctypes.c_uint8(PROTO_MAP[proto_str]),
                ip_to_u32_inverted(ip_src),
                ctypes.c_uint16(socket.htons(port_dst))
            )
            blocked_rules3[key] = ctypes.c_uint32(1)
            return jsonify({"message": f"Regla añadida: bloquear IP {ip_src} hacia puerto {port_dst} para {proto_str}"}), 200

        # Error: combinación inválida de campos
        else:
            return jsonify({"error": "Campos incompletos o inválidos. Indique SOLO protocolo, SOLO IP de origen o ambos junto con puerto destino. Mayor flexibilidad en futuras versiones..."}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/add_rule_pass', methods=['POST'])
def add_rule_pass():
    data = request.get_json()
    ip_src = data.get("ip_source")  # IP de origen
    port_dst = data.get("port_dst")  # Puerto de destino
    proto_str = data.get("proto", "").lower()  # Protocolo en minúscula

    try:
        # Caso 1: Solo protocolo especificado
        if proto_str and not ip_src and not port_dst:
            if proto_str not in PROTO_MAP:
                return jsonify({"error": "Protocolo inválido"}), 400
            key = ctypes.c_uint8(PROTO_MAP[proto_str])
            allowed_rules1[key] = ctypes.c_uint32(1)
            return jsonify({"message": f"Regla añadida: permitir protocolo {proto_str}"}), 200

        # Caso 2: Solo IP fuente especificada
        elif ip_src and not port_dst and not proto_str:
            ip_src_u32 = ip_to_u32_inverted(ip_src)
            key = ctypes.c_uint32(ip_src_u32)
            allowed_rules2[key] = ctypes.c_uint32(1)
            return jsonify({"message": f"Regla añadida: permitir IP de origen {ip_src}"}), 200

        # Caso 3: IP, puerto y protocolo especificados (original)
        elif ip_src and port_dst and proto_str:
            if proto_str not in PROTO_MAP:
                return jsonify({"error": "Protocolo inválido"}), 400
            key = allowed_rules3.Key(
                ctypes.c_uint8(PROTO_MAP[proto_str]),
                ip_to_u32_inverted(ip_src),
                ctypes.c_uint16(socket.htons(port_dst))
            )
            allowed_rules3[key] = ctypes.c_uint32(1)
            return jsonify({"message": f"Regla añadida: permitir IP {ip_src} hacia puerto {port_dst} para {proto_str}"}), 200

        # Error: combinación inválida de campos
        else:
            return jsonify({"error": "Campos incompletos o inválidos. Indique SOLO protocolo, SOLO IP de origen o ambos junto con puerto destino. Mayor flexibilidad en futuras versiones..."}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Endpoint para listar reglas activas
@app.route('/list_rules', methods=['GET'])
def list_rules():
    try:
        allowed = []
        for key, value in allowed_rules1.items():
            # Convertir la IP invertida a formato legible
            proto = [k for k, v in PROTO_MAP.items() if v == key.proto][0]  # Convertir proto numérico a string
            allowed.append({"proto": proto, "ip_source": "0.0.0.0", "port_dst": 0, "action": "allow"})
        for key, value in allowed_rules2.items():
            # Convertir la IP invertida a formato legible
            ip_src_bytes = struct.pack("!I", key.ip_src)
            ip_src = socket.inet_ntoa(ip_src_bytes[::-1])  # Deshacer inversión de bytes
            allowed.append({"proto": "all", "ip_source": ip_src, "port_dst": 0, "action": "allow"})
        for key, value in allowed_rules3.items():
            # Convertir la IP invertida a formato legible
            ip_src_bytes = struct.pack("!I", key.ip_src)
            ip_src = socket.inet_ntoa(ip_src_bytes[::-1])  # Deshacer inversión de bytes
            port_dst = socket.ntohs(key.port_dst) # Convertir el puerto a formato host
            proto = [k for k, v in PROTO_MAP.items() if v == key.proto][0]  # Convertir proto numérico a string
            allowed.append({"proto": proto, "ip_source": ip_src, "port_dst": port_dst, "action": "allow"})

        blocked = []
        for key, value in blocked_rules1.items():
            # Convertir la IP invertida a formato legible
            proto = [k for k, v in PROTO_MAP.items() if v == key.proto][0]  # Convertir proto numérico a string
            blocked.append({"proto": proto, "ip_source": "0.0.0.0", "port_dst": 0, "action": "block"})
        for key, value in blocked_rules2.items():
            # Convertir la IP invertida a formato legible
            ip_src_bytes = struct.pack("!I", key.ip_src)
            ip_src = socket.inet_ntoa(ip_src_bytes[::-1])  # Deshacer inversión de bytes
            blocked.append({"proto": "all", "ip_source": ip_src, "port_dst": 0, "action": "block"})
        for key, value in blocked_rules3.items():
            # Convertir la IP invertida a formato legible
            ip_src_bytes = struct.pack("!I", key.ip_src)
            ip_src = socket.inet_ntoa(ip_src_bytes[::-1])  # Deshacer inversión de bytes
            port_dst = socket.ntohs(key.port_dst) # Convertir el puerto a formato host
            proto = [k for k, v in PROTO_MAP.items() if v == key.proto][0]  # Convertir proto numérico a string
            blocked.append({"proto": proto, "ip_source": ip_src, "port_dst": port_dst, "action": "block"})

        return jsonify({"rules": {"blocked": blocked, "allowed": allowed}}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/delete_rule', methods=['POST'])
def delete_rule():
    try:
        # Recibir datos del cliente
        data = request.get_json()
        action = data.get("action")
        ip_source = data.get("ip_source")
        port_dst = data.get("port_dst")
        proto_str = data.get("proto", "").lower()

        print(f"Datos recibidos en /delete_rule: {data}")

        # Validar acción
        if action not in ["block", "allow"]:
            return jsonify({"error": "Acción inválida. Use 'block' o 'allow'"}), 400

        # Seleccionar la tabla según la acción
        target_table_1 = blocked_rules1 if action == "block" else allowed_rules1
        target_table_2 = blocked_rules2 if action == "block" else allowed_rules2
        target_table_3 = blocked_rules3 if action == "block" else allowed_rules3

        # Caso 1: Eliminar por IP + Puerto + Protocolo
        if ip_source and port_dst and proto_str:
            key = target_table_3.Key(
                ctypes.c_uint8(PROTO_MAP[proto_str]),
                ip_to_u32_inverted(ip_source),
                ctypes.c_uint16(socket.htons(port_dst))
            )
            del target_table_3[key]
            return jsonify({"message": f"Regla eliminada: {action} IP {ip_source} puerto {port_dst} protocolo {proto_str}"}), 200

        # Caso 2: Eliminar por solo IP
        elif ip_source and not port_dst and proto_str == "all":
            key = ctypes.c_uint32(ip_to_u32_inverted(ip_source))
            del target_table_2[key]
            return jsonify({"message": f"Regla eliminada: {action} IP {ip_source}"}), 200

        # Caso 3: Eliminar por solo Protocolo
        elif proto_str and ip_source == "0.0.0.0" and not port_dst:
            key = ctypes.c_uint8(PROTO_MAP[proto_str])
            del target_table_1[key]
            return jsonify({"message": f"Regla eliminada: {action} protocolo {proto_str}"}), 200

        # Si no coincide con ninguno de los casos válidos
        return jsonify({"error": "Campos incompletos o inválidos"}), 400

    except KeyError:
        return jsonify({"error": "Regla no encontrada"}), 404
    except Exception as e:
        print(f"Error en /delete_rule: {str(e)}")
        return jsonify({"error": str(e)}), 500



if __name__ == '__main__':
    try:
        print(f"Programa eBPF asociado a la interfaz {INTERFACE}. Presiona Ctrl+C para salir.")
        app.run(host='0.0.0.0', port=5027, ssl_context=('cert_back.pem', 'key_back.pem'))
    except KeyboardInterrupt:
        cleanup(None, None)
