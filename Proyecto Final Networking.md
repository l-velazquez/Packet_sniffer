# Packet Sniffer
Programador: Luis F. Velázquez Sosa
Clase: CCOM 4205
Prof. Jose Ortiz
### Discripcion
El sniffer de paquetes implementado en el código proporcionado captura paquetes de la red mediante un socket raw y cuenta el número de diferentes tipos de protocolos que encuentra. Cuenta el número de paquetes ARP, paquetes IP, paquetes TCP, paquetes UDP y diferentes tipos de protocolos de aplicación (HTTP, SSH, DNS, SMTP y otros) que ve.

Para capturar paquetes, el código crea un socket raw y entra en un bucle para recibir continuamente paquetes mediante el método recvfrom. Para cada paquete recibido, extrae el encabezado Ethernet y comprueba el campo de protocolo siguiente para determinar si el paquete es un paquete ARP, un paquete IP o algo más. Si el paquete es un paquete IP, extrae el encabezado IP y comprueba el campo de protocolo para determinar si el paquete es un paquete TCP, un paquete UDP o algo más. Si el paquete es un paquete TCP o UDP, extrae el encabezado TCP o UDP y comprueba los puertos de origen y destino para determinar el tipo de protocolo de aplicación utilizado.

Al final hacemos Ctr+C y te despliega todo los packetes que capturo.



Para correr el codigo debes estar en root o hacer

```sh
sudo python3 Packet-sniffer-Luis-Velazquez.py
```

Sources Used:
https://medium.com/kernel-space/unpacking-a-raw-packet-ethernet-frame-part-1-e91033e745a4
https://medium.com/kernel-space/unpacking-a-raw-packet-network-packet-part-2-de0ac30e4935
    To be able to know who to extract the necessary information.
https://github.com/hkoushik/raw-packet
    example code that has the necessary way to extract the information using unpack.