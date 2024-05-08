import pyshark  as pys
import psutil
import tkinter as tk
import tailwall
import comunication
from time import sleep 
from os import system as sys   


def getprocess(ip_address, port):
    """
    Purpose: Obtener el nombre del proceso asociado con una dirección IP y un puerto.

    Args:
        ip_address (str): Dirección IP del proceso.
        port (int): Puerto del proceso.

    Comportamiento:
        1. Itera sobre todas las conexiones de red activas.
        2. Para cada conexión, comprueba si la dirección IP y el puerto coinciden con los proporcionados.
        3. Si se encuentra una coincidencia, devuelve el nombre del proceso asociado con la conexión.
        4. Si no se encuentra ninguna coincidencia, devuelve "Desconocido".
    """
    try:
        for coon in psutil.net_connections(): #itinera las conexiones socket que tengan un flujo
            if coon.laddr.ip == ip_address and coon.laddr.port == port:
                return psutil.Process(coon.pid).name()
    except psutil.NoSuchProcess:
        return psutil.Process(coon.pid)
    return "Desconocido"
def packet_callback(pkt):
    """
    Purpose: Procesar paquetes de red capturados.

    Args:
        pkt (pyshark.packet.Packet): Paquete capturado.

    Variables globales:
        src_ip (str): Dirección IP de origen del paquete.
        src_port (int): Puerto de origen del paquete.
        src_process (str): Nombre del proceso asociado con la dirección IP y el puerto de origen.
        dst_ip (str): Dirección IP de destino del paquete.
        dst_port (int): Puerto de destino del paquete.
        dst_process (str): Nombre del proceso asociado con la dirección IP y el puerto de destino.

    Comportamiento:
        1. Comprueba si el paquete contiene una capa de protocolo de Internet (IP).
        2. Si el paquete contiene una capa IP, extrae las direcciones IP de origen y destino del paquete.
        3. Si el paquete contiene una capa de protocolo de control de transmisión (TCP) o de protocolo de datagramas de usuario (UDP), extrae los puertos de origen y destino del paquete.
        4. Llama a la función `getprocess` para obtener los nombres de los procesos asociados con las direcciones IP y los puertos de origen y destino.
        5. Imprime la siguiente información:
            * Dirección IP de origen, puerto y nombre del proceso.
            * Dirección IP de destino, puerto y nombre del proceso.
    """
    global src_ip, src_port, src_process, dst_ip, dst_port, dst_process
    if "IP" in pkt:
        src_ip = pkt["IP"].src
        dst_ip = pkt["IP"].dst
        src_port = None
        dst_port = None
        if "TCP" in pkt:
            src_port = pkt["TCP"].srcport
            dst_port = pkt["TCP"].dstport
        elif "UDP" in pkt:
            src_port = pkt["UDP"].srcport
            dst_port = pkt["UDP"].dstport
        src_process = getprocess(src_ip, int(src_port))
        dst_process = getprocess(dst_ip, int(dst_port))
        if src_process == "Unknown":
            src_process = ""
        print(f"Desde: {src_ip} Puerto:{src_port} ({src_process}) hacia {dst_ip} Puerto:{dst_port} ({dst_process})")
        sleep(2)
        
        
if __name__ == "__main__":
    try:
        sys("cls") #windows
    except:
        sys("clear") #linux
    print("Argos v1.0 By astartes developer")
    print("[+]Selecciona Tu Interfaz (Ejemplo Ethernet):\n")
    interfaces = psutil.net_if_addrs() #get the interfaces / obtiene las interfaces
    for interfaces, addr in interfaces.items():
        print(f"[+]{interfaces}")
    interface = input("[+]:")
    (pys.LiveCapture(interface=interface, bpf_filter="ip")).apply_on_packets(
        packet_callback
    ) #llama a la escucha de la interfaz seleccionada / call the funcion whit the interface selected