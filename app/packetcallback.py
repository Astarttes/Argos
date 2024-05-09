import psutil
import pyshark
from time import sleep
from datetime import datetime 


class PacketAnalyzer:
    def __init__(self, interface):
        self.interface = interface
        self.src_ip = None
        self.src_port = None
        self.src_process = None
        self.dst_ip = None
        self.dst_port = None
        self.dst_process = None

    def get_process_name(self, pid):
        try:
            return psutil.Process(pid).name()
        except psutil.NoSuchProcess:
            return "Desconocido"

    def get_process_from_connection(self, ip_address, port):
        for conn in psutil.net_connections(kind='inet'):
            try:
                if (conn.laddr.ip == ip_address and conn.laddr.port == port) or \
                   (conn.raddr and conn.raddr.ip == ip_address and conn.raddr.port == port):
                    return self.get_process_name(conn.pid)
            except psutil.NoSuchProcess:
                pass
        return "Desconocido"

    def get_process(self, ip_address, port):
        process_name = "Desconocido"
        try:
            # Buscamos la conexión basada en la dirección IP y el puerto
            process_name = self.get_process_from_connection(ip_address, port)
            
            # Si no se encuentra, intentamos buscar en las conexiones TCP establecidas
            if process_name == "Desconocido" and ip_address != "0.0.0.0":
                for conn in psutil.net_connections(kind='tcp'):
                    try:
                        if (conn.laddr.ip == ip_address and conn.laddr.port == port) or \
                           (conn.raddr and conn.raddr.ip == ip_address and conn.raddr.port == port):
                            process_name = self.get_process_name(conn.pid)
                            break
                    except psutil.NoSuchProcess:
                        pass
        except (PermissionError, psutil.AccessDenied):
            pass
        
        return process_name

    def packet_callback(self, pkt):
        if "IP" in pkt:
            self.src_ip = pkt["IP"].src
            self.dst_ip = pkt["IP"].dst
            self.src_port = None
            self.dst_port = None
            protocol = "UDP" if "UDP" in pkt else "TCP"
            packet_size = len(pkt)
            
            if "TCP" in pkt:
                self.src_port = pkt["TCP"].srcport
                self.dst_port = pkt["TCP"].dstport
            elif "UDP" in pkt:
                self.src_port = pkt["UDP"].srcport
                self.dst_port = pkt["UDP"].dstport
            self.src_process = self.get_process(self.src_ip, int(self.src_port))
            self.dst_process = self.get_process(self.dst_ip, int(self.dst_port))
            if self.src_process == "Desconocido":
                self.src_process = ""
            sleep(2)
            print(f"""Time: 
                  {(datetime.now()).strftime("%H:%M:%S")} 
                  Protocolo: {protocol} 
                  Desde: {self.src_ip}:{self.src_port} ({self.src_process}) 
                  hacia {self.dst_ip}:{self.dst_port} ({self.dst_process}) 
                  Tamaño: {packet_size} bytes""")

    def start_capture(self):
        capture = pyshark.LiveCapture(interface=self.interface, bpf_filter="ip")
        capture.apply_on_packets(self.packet_callback)
