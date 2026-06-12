# 🔀 VTP Attack — Seguridad de Redes

<div align="center">

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge\&logo=python)
![Scapy](https://img.shields.io/badge/Scapy-Packet%20Crafting-green?style=for-the-badge)
![Cisco](https://img.shields.io/badge/Cisco-IOL%20Switches-blueviolet?style=for-the-badge\&logo=cisco)
![PNETLab](https://img.shields.io/badge/PNETLab-Lab%20Environment-orange?style=for-the-badge)
![License](https://img.shields.io/badge/Uso-Educativo-red?style=for-the-badge)

**Sael Germán García** | Matrícula: `2025-0725`
Asignatura: Seguridad de Redes | Profesor: Jonathan Rondón
Instituto Tecnológico de las Américas — ITLA | 2026

</div>

---

## 📋 Descripción del Ataque

El **VTP Attack** explota una debilidad del protocolo **VTP (VLAN Trunking Protocol)** cuando un atacante logra conectarse a un puerto configurado como **trunk** dentro del mismo dominio VTP.

VTP es utilizado en redes Cisco para propagar información de VLANs entre switches. Sin embargo, si un dispositivo no autorizado logra enviar anuncios VTP con el mismo dominio y un **Configuration Revision** superior, los switches pueden aceptar una base de datos VLAN falsa.

En este laboratorio se demuestra cómo un atacante puede:

|      Acción      | Resultado                                                         |
| :--------------: | ----------------------------------------------------------------- |
| Agregar una VLAN | Se crea la VLAN `999 HACKEADO` en el dominio VTP                  |
|  Borrar una VLAN | Se elimina la VLAN `20 RRHH` de la base VLAN                      |
|    Propagación   | Los cambios se replican desde SW1-CORE hacia SW2                  |
|    Mitigación    | Se aplica VTP Transparent y se elimina el trunk hacia el atacante |

> 💡 **Punto clave:** VTP confía en actualizaciones que pertenezcan al mismo dominio y tengan un número de revisión superior. Por eso, un puerto trunk expuesto representa un riesgo crítico.

---

## 🗺️ Topología de Red

La práctica fue realizada en **PNETLab**, utilizando switches Cisco IOL, routers, VPCs y una máquina atacante Linux.

```text
                         INTERNET
                            |
                           R2
                            |
                           R1
                            |
                         SW1-CORE
                    /        |        \
                 SW2        VPC2      Atacante Linux
                  |
                 VPC1
```

### 📌 Descripción general

|   Dispositivo  | Rol             | Interfaz relevante | Descripción                             |
| :------------: | --------------- | ------------------ | --------------------------------------- |
|    SW1-CORE    | VTP Server      | e0/2, e0/3         | Switch principal del dominio VTP        |
|       SW2      | VTP Client      | e0/0               | Switch cliente que sincroniza VLANs     |
| Atacante Linux | Atacante        | ens3               | Máquina que ejecuta el script con Scapy |
|      VPC1      | Host cliente    | eth0               | Host conectado a SW2                    |
|      VPC2      | Host cliente    | eth0               | Host conectado a SW1-CORE               |
|       R1       | Router interno  | e0/1               | Router conectado a SW1-CORE             |
|       R2       | Router superior | e0/0, e0/1         | Router conectado hacia Internet         |

---

## 📊 Matriz de Direccionamiento

|    Elemento    |   Dirección IP  |       Interfaz       | Detalle                                            |
| :------------: | :-------------: | :------------------: | -------------------------------------------------- |
|    SW1-CORE    |  `10.25.7.1/24` |        VLAN 1        | Switch en modo VTP Server                          |
|       SW2      |  `10.25.7.2/24` |        VLAN 1        | Switch en modo VTP Client                          |
| Atacante Linux | Interfaz `ens3` | Conectado a SW1 e0/3 | Equipo que genera paquetes VTP                     |
|   Dominio VTP  |      `LAB`      |           —          | Dominio usado en el laboratorio                    |
|   Versión VTP  |       `1`       |           —          | Versión utilizada por compatibilidad con Cisco IOL |

---

## 🧩 VLANs del Laboratorio

| VLAN ID |       Nombre       |        Estado        | Descripción                     |
| :-----: | :----------------: | :------------------: | ------------------------------- |
|    1    |       default      |       Existente      | VLAN predeterminada             |
|    10   |       VENTAS       |       Existente      | VLAN de usuarios                |
|    20   |        RRHH        | Eliminada por ataque | VLAN objetivo del borrado       |
|   999   |      HACKEADO      |  Agregada por ataque | VLAN maliciosa creada con Scapy |
|   1002  |    fddi-default    |       Existente      | VLAN legacy predeterminada      |
|   1003  | token-ring-default |       Existente      | VLAN legacy predeterminada      |
|   1004  |   fddinet-default  |       Existente      | VLAN legacy predeterminada      |
|   1005  |    trnet-default   |       Existente      | VLAN legacy predeterminada      |

---

## ⚙️ Requisitos

```bash
# Sistema Operativo
Ubuntu Linux / Linux Desktop en PNETLab

# Dependencias necesarias
sudo apt update
sudo apt install -y python3 python3-pip tcpdump
sudo pip3 install scapy

# Privilegios requeridos
sudo / root

# Interfaz usada por el atacante
ens3
```

---

## 🔧 Configuración Previa

### Configuración de SW1-CORE

```cisco
enable
configure terminal
hostname SW1-CORE

vtp domain LAB
vtp mode server
vtp version 1

vlan 10
name VENTAS
exit

vlan 20
name RRHH
exit

interface ethernet 0/1
switchport mode access
switchport access vlan 10
no shutdown
exit

interface ethernet 0/2
switchport trunk encapsulation dot1q
switchport mode trunk
switchport trunk allowed vlan all
no shutdown
exit

interface ethernet 0/3
switchport trunk encapsulation dot1q
switchport mode trunk
switchport trunk allowed vlan all
no shutdown
exit

interface vlan 1
ip address 10.25.7.1 255.255.255.0
no shutdown
exit

end
write memory
```

### Configuración de SW2

```cisco
enable
configure terminal
hostname SW2

vtp domain LAB
vtp mode client
vtp version 1

interface ethernet 0/0
switchport trunk encapsulation dot1q
switchport mode trunk
switchport trunk allowed vlan all
no shutdown
exit

interface ethernet 0/1
switchport mode access
switchport access vlan 10
no shutdown
exit

interface vlan 1
ip address 10.25.7.2 255.255.255.0
no shutdown
exit

end
write memory
```

---

## 🚀 Uso del Script

### Agregar VLAN maliciosa

```bash
sudo python3 vtp_attack_scratch.py add 999 HACKEADO
```

Verificación en SW1-CORE y SW2:

```cisco
show vlan brief | include 10|20|999
show vtp status
```

Resultado esperado:

```text
999    HACKEADO    active
```

---

### Borrar VLAN existente

```bash
sudo python3 vtp_attack_scratch.py delete 20
```

Verificación:

```cisco
show vlan brief | include 10|20|999
show vtp status
```

Resultado esperado:

```text
La VLAN 20 RRHH ya no aparece en la base VLAN.
La VLAN 999 HACKEADO permanece activa.
```

---

## 🔬 ¿Cómo funciona el script?

| Paso | Descripción                                                                                |
| :--: | ------------------------------------------------------------------------------------------ |
|  1️⃣ | Escucha anuncios VTP en la interfaz `ens3`                                                 |
|  2️⃣ | Si no recibe anuncios automáticamente, envía un **VTP Request**                            |
|  3️⃣ | Captura un **VTP Subset Advertisement** real del dominio `LAB`                             |
|  4️⃣ | Extrae la base VLAN actual desde el paquete capturado                                      |
|  5️⃣ | Modifica la base de datos VLAN en memoria                                                  |
|  6️⃣ | Para agregar VLAN, inserta la VLAN `999 HACKEADO`                                          |
|  7️⃣ | Para borrar VLAN, elimina la VLAN `20 RRHH`                                                |
|  8️⃣ | Incrementa el **Configuration Revision**                                                   |
|  9️⃣ | Calcula un **MD5 digest** válido para la nueva base VTP                                    |
|  🔟  | Construye desde cero paquetes **VTP Summary Advertisement** y **VTP Subset Advertisement** |
|   ✅  | Envía los paquetes con Scapy hacia la MAC multicast Cisco `01:00:0c:cc:cc:cc`              |

---

## 🧠 Parámetros principales del script

|    Parámetro   |     Valor usado     | Descripción                               |
| :------------: | :-----------------: | ----------------------------------------- |
|     `IFACE`    |        `ens3`       | Interfaz del atacante conectada al switch |
|    `DOMAIN`    |        `LAB`        | Dominio VTP objetivo                      |
|    `DST_MAC`   | `01:00:0c:cc:cc:cc` | Dirección multicast Cisco usada por VTP   |
|  `UPDATER_IP`  |     `10.25.7.1`     | Identidad del actualizador VTP            |
|   VTP Version  |         `1`         | Versión utilizada en el laboratorio       |
|  VLAN agregada |    `999 HACKEADO`   | VLAN maliciosa creada durante la prueba   |
| VLAN eliminada |      `20 RRHH`      | VLAN eliminada mediante el ataque         |

---

## 🧪 Verificación técnica con tcpdump

Para comprobar que el atacante está enviando anuncios VTP reales:

```bash
sudo tcpdump -i ens3 -nn -e 'ether dst 01:00:0c:cc:cc:cc and ether[20:2] = 0x2003'
```

Salida esperada:

```text
VTPv1, Message Summary advertisement
VTPv1, Message Subset advertisement
```

Esto confirma que el script está enviando paquetes VTP usando encapsulación 802.3 + LLC/SNAP hacia la dirección multicast Cisco.

---

## 🛡️ Contramedidas

### 1. Cambiar VTP a modo Transparent

```cisco
SW1-CORE(config)# vtp mode transparent
```

El modo **transparent** evita que el switch aplique bases VLAN recibidas desde otros dispositivos mediante VTP.

---

### 2. Evitar trunks hacia equipos no autorizados

```cisco
SW1-CORE(config)# interface ethernet 0/3
SW1-CORE(config-if)# switchport mode access
SW1-CORE(config-if)# switchport access vlan 10
SW1-CORE(config-if)# switchport nonegotiate
SW1-CORE(config-if)# spanning-tree bpduguard enable
SW1-CORE(config-if)# end
SW1-CORE# write memory
```

---

### 3. Verificación posterior

```cisco
show vtp status
show interfaces trunk
show interfaces ethernet 0/3 switchport
```

Resultado esperado:

| Control              | Resultado esperado              |
| -------------------- | ------------------------------- |
| VTP Mode             | Transparent                     |
| Puerto del atacante  | Access                          |
| DTP                  | Deshabilitado con `nonegotiate` |
| BPDU Guard           | Habilitado                      |
| Trunk hacia atacante | Eliminado                       |

---

## 📁 Archivos del Repositorio

|                                       Archivo / Carpeta                                      | Descripción                               |
| :------------------------------------------------------------------------------------------: | ----------------------------------------- |
|                       [`vtp_attack_scratch.py`](vtp_attack_scratch.py)                       | Script principal del ataque VTP con Scapy |
| [`SaelGermanGarcia_2025-0725_VTPAttack_P1.pdf`](SaelGermanGarcia_2025-0725_VTPAttack_P1.pdf) | Documentación técnica profesional         |
|       [`Capturas de Pantalla VTP Attacks/`](Capturas%20de%20Pantalla%20VTP%20Attacks/)       | Evidencias gráficas del laboratorio       |
|                                          `README.md`                                         | Documentación principal del repositorio   |

---

## 🖼️ Capturas de Pantalla

Las evidencias del laboratorio se encuentran en la carpeta:

📁 [`Capturas de Pantalla VTP Attacks`](Capturas%20de%20Pantalla%20VTP%20Attacks/)

Evidencias incluidas:

* 📸 Topología PNETLab del laboratorio VTP Attack
* 📸 Estado inicial de SW1-CORE con VLANs 10 y 20
* 📸 Estado inicial de SW2 como VTP Client
* 📸 Enlaces trunk activos en SW1-CORE
* 📸 Enlace trunk activo en SW2 hacia SW1-CORE
* 📸 Ejecución del script agregando la VLAN 999 HACKEADO
* 📸 Verificación en SW1-CORE de VLAN 999 agregada correctamente
* 📸 Verificación en SW2 de propagación mediante VTP Client
* 📸 Ejecución del script eliminando la VLAN 20 RRHH
* 📸 Verificación posterior con VLAN 20 eliminada y VLAN 999 conservada
* 📸 Aplicación de contramedida en SW1-CORE

---

## 📎 Recursos

📄 **Documentación Técnica:**
[Ver Informe PDF](SaelGermanGarcia_2025-0725_VTPAttack_P1.pdf)

▶️ **Playlist de YouTube:**
[Ver demostraciones en YouTube](https://www.youtube.com/playlist?list=PLV_dKVnYXf6f67jGkXDf8d4dPSeYV39qM)

---

## ⚠️ Aviso de Uso Ético

Este proyecto fue desarrollado únicamente con fines educativos y académicos dentro de un entorno controlado de laboratorio en PNETLab.

No debe ejecutarse en redes reales, corporativas o de terceros sin autorización explícita. El uso indebido de este material puede causar interrupciones de servicio, pérdida de conectividad y alteraciones en la infraestructura de red.

---

## 📚 Referencias

1. Cisco Systems. *VLAN Trunking Protocol Configuration and Troubleshooting Documentation*.
2. Scapy Project. *Scapy: Packet crafting and network manipulation framework*. https://scapy.net/
3. PNETLab. *Network Emulation Platform for Network Labs*.
4. Reconocimiento especial: Troubleshooting, base del script y documentación apoyada en Inteligencia Artificial.

---

<div align="center">

### ✅ VTP Attack completado exitosamente

**Sael Germán García — 2025-0725**
Seguridad de Redes | ITLA | 2026

</div>
