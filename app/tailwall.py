import pyshark
import threading

class Firewall:
    def __init__(self, interface, blocking=True):
        self.interface = interface
        self.blocking = blocking
        self.allowed_ports = {80, 443}  # Puertos permitidos (HTTP, HTTPS)
        self.capture_thread = None

    def start(self):
        self.capture_thread = threading.Thread(target=self._start_capture)
        self.capture_thread.start()

    def _start_capture(self):
        capture = pyshark.LiveCapture(interface=self.interface)
        for packet in capture.sniff_continuously():
            if 'TCP' in packet and 'IP' in packet:
                src_port = int(packet.tcp.srcport)
                dst_port = int(packet.tcp.dstport)
                if src_port not in self.allowed_ports and dst_port not in self.allowed_ports:
                    if self.blocking:
                        print(f"Paquete bloqueado: {packet.ip.src}:{src_port} -> {packet.ip.dst}:{dst_port}")
                        packet.drop()
                    else:
                        print(f"Paquete detectado: {packet.ip.src}:{src_port} -> {packet.ip.dst}:{dst_port}")
                else:
                    print(f"Paquete permitido: {packet.ip.src}:{src_port} -> {packet.ip.dst}:{dst_port}")

    def stop(self):
        if self.capture_thread:
            self.capture_thread.join()
