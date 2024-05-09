import psutil
from time import sleep
from packetcallback import PacketAnalyzer
from os import system as sys
from server import start_server
import threading

def presentation():
    try:
        sys("cls")  # clear terminal on Windows
    except:
        sys("clear")  # on Linux
    print("/////////////////////////////////////////")
    print("/// Argos - Alpha v1.0 - By Astartes  ///")
    print("/////////////////////////////////////////")
    sleep(3)

def initpackettracer():
    print("/////////////////////////////////////////")
    print("/// Selecciona la interfaz:           ///")
    interfaces = psutil.net_if_addrs() #get the interfaces / obtiene las interfaces
    for interface, addr in interfaces.items():
        print(f"[+]{interface}")
    interface = input("[+]:")
    analyzer = PacketAnalyzer(interface)
    analyzer.start_capture()

def comunication():
    pass

def wall():
    pass

def makeserver():
    start_server()

def menu():
    try:
        sys("cls")  # clear terminal on Windows
    except:
        sys("clear")  # on Linux
    options = {
        1: initpackettracer,
        2: comunication,
        3: wall,
        4: makeserver
    }

    print("/////////////////////////////////////////")
    print("/// Selecciona Una opcion:            ///")
    print("///                                   ///")
    print("/// 1: Iniciar Monitoreo De Red       ///")
    print("/// 2: Configurar Alertas             ///")
    print("/// 3: Iniciar/Configurar Firewall    ///")
    print("/// 4: Ver gráfica de uso de recursos ///")
    print("///                                   ///")
    print("/////////////////////////////////////////")
    option = int(input("/// [+]: "))
    if option not in options:
        print("/// Seleccion Erronea")
        return

    options[option]()

if __name__ == "__main__":
    presentation()
    menu_thread = threading.Thread(target=menu)
    menu_thread.start()
