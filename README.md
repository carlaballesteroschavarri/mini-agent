<h1 align="center"> Mini SNMP Agent with Notifications</h1>



Descripción del proyecto
Este proyecto implementa un agente SNMP personalizado en Python utilizando la biblioteca pysnmp, psutil y asyncio. Objetivos:

- Expone objetos gestionados (manager, managerEmail, cpuUsage, cpuThreshold, eventTime).

- Envía una notificación SNMP (trap) y un correo electrónico cuando el uso de CPU supera un umbral configurado.

- Persiste su estado en un archivo JSON.

- Soporta SNMPv1 y SNMPv2c, con comunidades públicas (RO) y privadas (RW).

La práctica integra modelado MIB, programación con pysnmp, y manejo real de notificaciones.

Estructura del proyecto 
----------------------------------------------------------------------------------------------------------------------------------------------------

```text
snmp_agent/
                │                                                                                                                                                  
                ├── mini_agent.py              # Agente SNMP principal 
                ├── mib_state.json             # Estado persistente de los objetos
                ├── MYAGENT-MIB.txt            # MIB personalizada
                ├── pruebas.py                 # Script de pruebas SNMP 
                └── README.md                  # Documentación del proyecto
```
Funcionalidades: 
----------------------------------------------------------------------------------------------------------------------------------------------------
- Modelo de información (MIB personalizada): Implementa objetos escalares bajo el grupo myAgentGroup con tipos DisplayString, Integer32 y DateandTime
- Los comandos SNMP: tienen soporte para GET, GETNEXT y SET en los objetos de gestión
- Monitoreo asíncrono: actualiza el valor de CPUUsage cada 5 segundos utilizando psutil dentro de una tarea asyncio
- Notificación inteligente: envío de un TRAP SNMPv2c y un correo electrónico cuando cpuUsage supera cpuThreshold
- Gestión de email: envía alertas al correo del administrador (managerEmail) usando smtplib con servidor Gmail y SSL

Configuración
----------------------------------------------------------------------------------------------------------------------------------------------------
_Requisitos:_
Python 

_Librerías necesarias a instalar:_ <br>
pysnmp: manejo del PDU <br>
psutil: lectura del uso de CPU <br>
asyncio: concurrencia asíncrona y tarea periódica <br>
smtplib: envío gmail


Ejecución del agente SNMP
-----------------------------------------------------------------------------------------------------------------------------------------------------

_Comunidades de acceso:_
- public (solo lectura)
- private (lectura y escritura)

_Direcciones:_ <br>
Agente está configurado para escuchar en el puerto UDP 1161<br>
Envía traps al destino por defecto 127.0.0.1:162

Al iniciarse, el agente crea (si no existe) el archivo mib_state.json con los valores por defecto y va guardando su estado en ese archivo: 
```text
DEFAULT_STORE = {
    "1.3.6.1.4.1.28308.1.1.0": ("DisplayString", "Admin"),
    "1.3.6.1.4.1.28308.1.2.0": ("DisplayString", "perezarancha28@gmail.com"),
    "1.3.6.1.4.1.28308.1.3.0": ("Integer32", 0),
    "1.3.6.1.4.1.28308.1.4.0": ("Integer32", 20),
    "1.3.6.1.4.1.28308.1.5.0": ("DateAndTime", ""),
}
```

_Configuración de Email:_ <br>
El envío del correo electrónico requiere que ENABLE_EMAIL esté en True. <br>
La configuración actual utiliza credenciales de Gmail y el puerto 465 SSL. <br>
El código implementa una función send_email_gmail que utiliza la biblioteca smtplib. <br>
Se debe utilizar una cuenta de correo con contraseña de aplicación (App password) si se utiliza Gmail, ya que el código contiene un nombre de usuario (GMAIL_USER) y una contraseña (GMAIL_APP_PASS)

_Para iniciar el agente:_ <br>
python mini_agent.py <br>
Agente imprimirá: <br>
Mini SNMP Agent (pysnmp 7.1.4) <br>
Escuchando en UDP/1161 (comunidades: public/private)


_Objetos de Gestión (MIB):_ <br>
```text
OID base: 1.3.6.1.4.1.28308.1 <br>
    Manager:      .1.1.0 RW (nombre del administrador) <br>
    ManagerEmail: .1.2.0 RW (Correo del administrador) <br>
    cpuUsage:     .1.3.0 RO (Uso actual de CPU) <br>
    cpuThreshold: .1.4.0 RW (Umbral de alerta de CPU) <br>
    eventTime:    .1.5.0 RO (Fecha/hora del último evento) <br>
```
Funcionamiento interno:
---------------------------------------------------------------------------------------------------------------------------------------------------------------------
1. Monitoreo periódico:
Cada 5 segundos, el agente mide el uso de CPU con psutil y actualiza el objeto cpuUsage. A su vez, escucha peticiones SNMP y ejecuta la función de respuesta correspondiente.
2. Superación de umbral:
Si cpuUsage > cpuThreshold, el agente: <br>
    Envía un TRAP SNMPv2c al destino configurado (por defecto localhost:162). <br>
    Envía un correo HTML con los detalles del evento. <br>
3. Persistencia:
Todos los valores de las variables RW (manager, managerEmail, cpuThreshold) se almacenan en mib_state.json para conservar su estado entre ejecuciones.

Pruebas SNMP (con herramientas snmp):
---------------------------------------------------------------------------------------------------------------------------------------------------------------------
Asumiendo que el agente se ejecuta en 127.0.0.1:1161. A continuación se muestran todos los comandos que se llevan a cabo durante la ejecución del archivo pruebas.py.

1. GET de todos los scalars con comunidad public <br>
snmpget -v2c -c public 127.0.0.1:1161 1.3.6.1.4.1.28308.1.1.0 <br>
snmpget -v2c -c public 127.0.0.1:1161 1.3.6.1.4.1.28308.1.2.0 <br>
snmpget -v2c -c public 127.0.0.1:1161 1.3.6.1.4.1.28308.1.3.0 <br>
snmpget -v2c -c public 127.0.0.1:1161 1.3.6.1.4.1.28308.1.4.0 <br>
snmpget -v2c -c public 127.0.0.1:1161 1.3.6.1.4.1.28308.1.5.0 <br>
2. SET con public<br>
snmpset -v2c -c public 127.0.0.1:1161 1.3.6.1.4.1.28308.1.1.0 s "NoDeberia" <br>
3. SET válidos con private <br>
snmpset -v2c -c private 127.0.0.1:1161 1.3.6.1.4.1.28308.1.1.0 s "CarlayArancha" <br>
snmpset -v2c -c private 127.0.0.1:1161 1.3.6.1.4.1.28308.1.2.0 s "carla.ballesteros64@gmail.com" <br>
snmpset -v2c -c private 127.0.0.1:1161 1.3.6.1.4.1.28308.1.4.0 i 50 <br>
4. SET sobre variable de solo lectura <br>
snmpset -v2c -c private 127.0.0.1:1161 1.3.6.1.4.1.28308.1.3.0 i 10 <br>
5. SET con tipo incorrecto <br>
snmpset -v2c -c private 127.0.0.1:1161 1.3.6.1.4.1.28308.1.4.0 s "bad-type" <br>
6. SET con valor fuera de rango (>100) <br>
snmpset -v2c -c private 127.0.0.1:1161 1.3.6.1.4.1.28308.1.4.0 i 200 <br>
7. SET sobre OID inexistente <br>
snmpset -v2c -c private 127.0.0.1:1161 1.3.6.1.4.1.28308.99.0 i 10 <br>
8. GETNEXT <br>
snmpgetnext -v2c -c public 127.0.0.1:1161 1.3.6.1.4.1.28308.1.1.0 <br>
9. SNMPWALK <br>
snmpwalk -v2c -c public 127.0.0.1:1161 1.3.6.1.4.1.28308.1 <br>
10. En la parte de alerta, un SET adicional para forzar trap y correo <br>
snmpset -v2c -c private 127.0.0.1:1161 1.3.6.1.4.1.28308.1.4.0 i 0 <br>
11. Restaurar el cpuThreshold original <br>
snmpset -v2c -c private 127.0.0.1:1161 1.3.6.1.4.1.28308.1.4.0 i 20 <br>


Autores:
-------------------------------------------------------------------------
Proyecto desarrollado para la asignatura GESTIÓN DE RED (25/26). <br>
Desarrollado por: Aranzazu Araguás Calvo, Carla Ballesteros Chavarri e Imene Mouri
