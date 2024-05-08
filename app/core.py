from packetcallback import packet_callback as pkc
import pyshark as pys
import psutil
from os import system as sys
from time import sleep

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
    interfaces = psutil.net_if_addrs()  # get the interfaces / obtiene las interfaces
    for interface, addr in interfaces.items():
        print(f"/// [+]{interface}")
    interface = input("/// [+]:")
    (
        pys.LiveCapture(
            interface=interface, bpf_filter="ip"
        )
    ).apply_on_packets(
        pkc
    )




def getprocess():
    """
    Purpose:
    """


def comunication():
    """
    Purpose:
    """


def wall():
    """
    Purpose:
    """


# end def

def menu():
    try:
        sys("cls")  # clear terminal on Windows
    except:
        sys("clear")  # on Linux
    options = {
        1: initpackettracer,
        2: getprocess,
        3: comunication,
        4: wall
    }

    while True:
        print("/////////////////////////////////////////")
        print("/// Selecciona Una opcion:            ///")
        print("///                                   ///")
        print("/// 1: Iniciar Monitoreo De Red       ///")
        print("/// 2: Monitorear Aplicaciones i/o    ///")
        print("/// 3: Configurar Alertas             ///")
        print("/// 4: Iniciar/Configurar Firewall    ///")
        print("///                                   ///")
        print("/////////////////////////////////////////")
        option = int(input("/// [+]:"))
        if option not in options:
            print("/// Seleccion Erronea")
            continue
        if option == 1:
            initpackettracer()



if __name__ == "__main__":
    presentation()
    menu()
