..........................................................................................................................................................................................................................................................................

                                            Mini SNMP Agent with Notifications
..........................................................................................................................................................................................................................................................................



Descripción del proyecto
Este proyecto implementa un agente SNMP personalizado en Python utilizando la biblioteca pysnmp, psutil y asyncio. Objetivos:

- Expone objetos gestionados (manager, managerEmail, cpuUsage, cpuThreshold, eventTime).

- Envía una notificación SNMP (trap) y un correo electrónico cuando el uso de CPU supera un umbral configurado.

- Persiste su estado en un archivo JSON.

- Soporta SNMPv1 y SNMPv2c, con comunidades públicas (RO) y privadas (RW).

La práctica integra modelado MIB, programación con pysnmp, y manejo real de notificaciones.

Estructura del proyecto 
----------------------------------------------------------------------------------------------------------------------------------------------------
snmp_agent/
                │                                                                                                                                                  
                ├── mini_agent.py              # Agente SNMP principal 
                ├── mib_state.json             # Estado persistente de los objetos
                ├── MYAGENT-MIB.txt            # MIB personalizada
                ├── pruebas.py                 # Script de pruebas SNMP 
                └── README.md                  # Documentación del proyecto

Funcionalidades: 
----------------------------------------------------------------------------------------------------------------------------------------------------
Modelo de información (MIB personalizada): Implementa objetos escalares bajo el grupo myAgentGroup con tipos DisplayString, Integer32 y DateandTime
Los comandos SNMP: tienen soporte para GET, GETNEXT y SET en los objetos de gestión
Monitoreo asíncrono: actualiza el valor de CPUUsage cada 5 segundos utilizando psutil dentro de una tarea asyncio
Notificación inteligente: envío de un TRAP SNMPv2c y un correo electrónico cuando cpuUsage supera cpuThreshold
Gestión de email: envía alertas al correo del administrador (managerEmail) usando smtplib con servidor Gmail y SSL

Configuración
----------------------------------------------------------------------------------------------------------------------------------------------------
Requisitos:
Python 

Librerías necesarias:
- pysnmp: manejo del PDU
- psutil: Lectura del uso de CPU
- asyncio: Concurrencia asíncrona y tarea periódica


Ejecución del agente SNMP
-----------------------------------------------------------------------------------------------------------------------------------------------------
pip install pysnmp psutil asyncio
pip install secure-smtplib

Comunidades de acceso:
-public (solo lectura)
-private (lectura y escritura)

Por defecto:
Agente está configurado para escuchar en el puerto UDP 1161
Envía traps al destino por defecto 127.0.0.1:162
Al iniciarse, el agente crea (Si no existe) el archivo mib_state.json con los valores por defecto: 
DEFAULT_STORE = {
    "1.3.6.1.4.1.28308.1.1.0": ("DisplayString", "Admin"),
    "1.3.6.1.4.1.28308.1.2.0": ("DisplayString", "perezarancha28@gmail.com"),
    "1.3.6.1.4.1.28308.1.3.0": ("Integer32", 0),
    "1.3.6.1.4.1.28308.1.4.0": ("Integer32", 20),
    "1.3.6.1.4.1.28308.1.5.0": ("DateAndTime", ""),
}
y va guardando su estado (valores escalares) en ese archivo

Configuración de Email:
El envío del correo electrónico requiere que ENABLE_EMAIL esté en True. La configuración actual utiliza credenciales de Gmail y el puerto 465 SSL. El código implementa una función send_email_gmail que utiliza la biblioteca smtplib.
Se debe utilizar una cuenta de correo con contraseña de aplicación (App password) si se utiliza Gmail, ya que el código contiene un nombre de usuario (GMAIL_USER) y una contraseña (GMAIL_APP_PASS)

Para iniciar el agente:
python mini_agent.py
Agente imprimirá: 
Mini SNMP Agent (pysnmp 7.1.4)
Escuchando en UDP/1161 (comunidades: public/private)


Objetos de Gestión (MIB)
- OID base: 1.3.6.1.4.1.28308.1
    Manager:      .1.1.0 RW (nombre del administrador)
    ManagerEmail: .1.2.0 RW (Correo del administrador)
    cpuUsage:     .1.3.0 RO (Uso actual de CPU)
    cpuThreshold: .1.4.0 RW (Umbral de alerta de CPU)
    eventTime:    .1.5.0 RO (Fecha/hora del último evento)

Funcionamiento interno:
---------------------------------------------------------------------------------------------------------------------------------------------------------------------
1. Monitoreo periódico:
Cada 5 segundos, el agente mide el uso de CPU con psutil y actualiza el objeto cpuUsage
2. Superación de umbral:
Si cpuUsage > cpuThreshold, el agente:
    Envía un TRAP SNMPv2c al destino configurado (por defecto localhost:162).
    Envía un correo HTML con los detalles del evento.
3. Persistencia:
Todos los valores de las variables RW (manager, managerEmail, cpuThreshold) se almacenan en mib_state.json para conservar su estado entre ejecuciones.

Pruebas SNMP (con herramientas snmp):
---------------------------------------------------------------------------------------------------------------------------------------------------------------------
Asumiendo que el agente se ejecuta en 127.0.0.1:1161

🔹 Lectura (GET / GETNEXT / WALK)
# Obtener nombre del manager
snmpget -v2c -c public 127.0.0.1:1161 1.3.6.1.4.1.28308.1.1.0

# Obtener uso de CPU
snmpget -v2c -c public 127.0.0.1:1161 1.3.6.1.4.1.28308.1.3.0

# Recorrer toda la tabla (WALK)
snmpwalk -v2c -c public 127.0.0.1:1161 1.3.6.1.4.1.28308.1

🔹 Escritura (SET)
snmpset -v2c -c private 127.0.0.1:1161 1.3.6.1.4.1.28308.1.2.0 s "carla.ballesteros64@gmail.com"
snmpset -v2c -c private 127.0.0.1:1161 1.3.6.1.4.1.28308.1.4.0 i 75

🔹 Prueba de Persistencia

    - Cambia un valor RW.

    - Detén y vuelve a iniciar el agente.

    - Comprueba que el cambio se ha conservado en mib_state.json.

🔹 Prueba de Notificación (TRAP + EMAIL)

   1.Configura un umbral bajo (ej. 10%):
    snmpset -v2c -c private 127.0.0.1:1161 1.3.6.1.4.1.28308.1.4.0 i 10

   2.Observa en la consola del agente:
    [TRAP] CPU=45% > 10% - Trap enviado 
    [EMAIL] Correo enviado correctamente a xxxxx

  3. Comprobar en la aplicación de correo que el mensaje llega

⚠️ Pruebas Negativas (Validación de Errores)
SET a variable RO	snmpset ... cpuUsage i 50	notWritable	17
Tipo incorrecto	snmpset ... cpuThreshold s "abc"	wrongType	7
Valor fuera de rango	snmpset ... cpuThreshold i 200	wrongValue	10
OID inexistente	snmpset ... 1.3.6.1.99.0 s "test"

Autores:
-------------------------------------------------------------------------
Proyecto desarrollado para la asignatura GESTIÓN DE RED (25/26).
Desarrollado por: Aranzazu Araguás Calvo, Carla Ballesteros Chavarri e Imene Mouri
