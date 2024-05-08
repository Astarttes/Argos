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

        print(f"Desde: {src_ip} Puerto:{src_port} hacia {dst_ip} Puerto:{dst_port}")
       