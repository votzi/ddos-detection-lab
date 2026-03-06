#!/usr/bin/env python3
"""
Menú de tráfico para Mininet
Ejecutar en Mininet CLI: py exec(open('scripts/traffic_menu.py').read())
"""

TARGET_IP = "10.1.1.2"

print("\n" + "="*50)
print("   GENERADOR DE TRÁFICO - MININET")
print("="*50)
print("\nTarget: %s\n" % TARGET_IP)
print("--- TRÁFICO NORMAL (Label = 0) ---")
print("  [1] Ping normal")
print("  [2] Ping continuo (lento)")
print("  [3] Transferencia HTTP simple")
print("  [4] wget descarga")
print("")
print("--- ATAQUES (Label = 1) ---")
print("  [5] SYN Flood")
print("  [6] ACK Flood")
print("  [7] UDP Flood")
print("  [8] ICMP Flood")
print("  [9] SYN+ACK Flood")
print("")
print("  [0] Salir\n")

opt = input("Opcion: ")

h1 = net.getNodeByName('h1')

if opt == "1":
    print("\n=== Ping Normal ===")
    print("Ctrl+C para detener\n")
    h1.cmd("ping -c 10 " + TARGET_IP)

elif opt == "2":
    print("\n=== Ping Continuo ===")
    print("Ctrl+C para detener\n")
    h1.cmd("ping " + TARGET_IP)

elif opt == "3":
    print("\n=== Transferencia HTTP ===")
    print("Iniciando servidor HTTP en segundo plano...")
    h1.cmd("python3 -m http.server 80 &")
    print("Descargando archivo...")
    h2.cmd("wget -O /dev/null http://10.1.1.1/index.html")
    h1.cmd("pkill -f 'http.server'")

elif opt == "4":
    print("\n=== wget Descarga ===")
    print("Ctrl+C para detener\n")
    h1.cmd("wget http://speedtest.tele2.net/1MB.zip -O /dev/null")

elif opt == "5":
    print("\n=== SYN Flood (ATAQUE) ===")
    print("Ctrl+C para detener\n")
    h1.cmd("hping3 --flood -S -p 80 " + TARGET_IP)

elif opt == "6":
    print("\n=== ACK Flood (ATAQUE) ===")
    print("Ctrl+C para detener\n")
    h1.cmd("hping3 --flood -A -p 80 " + TARGET_IP)

elif opt == "7":
    print("\n=== UDP Flood (ATAQUE) ===")
    print("Ctrl+C para detener\n")
    h1.cmd("hping3 --flood --udp -p 80 " + TARGET_IP)

elif opt == "8":
    print("\n=== ICMP Flood (ATAQUE) ===")
    print("Ctrl+C para detener\n")
    h1.cmd("ping -f " + TARGET_IP)

elif opt == "9":
    print("\n=== SYN+ACK Flood (ATAQUE) ===")
    print("Ctrl+C para detener\n")
    h1.cmd("hping3 --flood -S -A -p 80 " + TARGET_IP)

else:
    print("\nSaliendo...\n")
