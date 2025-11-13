import asyncio
import psutil
import time
import json
import os
import smtplib, ssl
from email.message import EmailMessage


from pysnmp.hlapi.v3arch.asyncio import *
from pysnmp.proto.api import v2c
from pysnmp.entity import config
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity.rfc3413 import cmdrsp, ntforg, context


# --------------------------------------------------------------------
# CONFIGURACIÓN EMAIL (Gmail)
# --------------------------------------------------------------------
ENABLE_EMAIL = True
GMAIL_USER = "aranchaaraguascalvojaca@gmail.com"
GMAIL_APP_PASS = "aige rnxt emvh ruuq"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465




def send_email_gmail(to_addr, subject, body):
    """Envía un correo HTML bonito con los datos del evento."""
    try:
        msg = EmailMessage()
        msg["From"] = GMAIL_USER
        msg["To"] = to_addr
        msg["Subject"] = subject


        html_content = f"""
        <html>
        <body style='font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;'>
            <div style='max-width: 600px; background: white; border-radius: 10px;
                        box-shadow: 0 0 10px rgba(0,0,0,0.1); padding: 20px;'>
                <h2 style='color: #d9534f;'>⚠️ Alerta SNMP - Umbral de CPU Superado</h2>
                <p>Estimado administrador,</p>
                <p>El agente SNMP ha detectado que el uso de CPU ha excedido el umbral configurado.</p>
                <table style='width: 100%; border-collapse: collapse;'>
                    <tr><td><strong>Uso de CPU:</strong></td><td>{body.split('|')[0]}</td></tr>
                    <tr><td><strong>Umbral:</strong></td><td>{body.split('|')[1]}</td></tr>
                    <tr><td><strong>Fecha y hora:</strong></td><td>{body.split('|')[2]}</td></tr>
                </table>
                <p>Por favor, revise el estado del sistema para evitar un posible sobrecalentamiento.</p>
                <hr>
                <p style='font-size: 12px; color: gray;'>Mensaje automático generado por el agente SNMP local.</p>
            </div>
        </body>
        </html>
        """


        msg.set_content("Alerta SNMP: CPU superó el umbral.")
        msg.add_alternative(html_content, subtype="html")


        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASS)
            server.send_message(msg)


        print(f"[EMAIL] Correo enviado correctamente a {to_addr}")


    except Exception as e:
        print(f"[ERROR] Fallo al enviar correo: {e}")




# --------------------------------------------------------------------
# PERSISTENCIA DEL ESTADO
# --------------------------------------------------------------------
STATE_FILE = "mib_state.json"


DEFAULT_STORE = {
    "1.3.6.1.4.1.28308.1.1.0": ("DisplayString", "Admin"),
    "1.3.6.1.4.1.28308.1.2.0": ("DisplayString", "perezarancha28@gmail.com"),
    "1.3.6.1.4.1.28308.1.3.0": ("Integer32", 0),
    "1.3.6.1.4.1.28308.1.4.0": ("Integer32", 20),
    "1.3.6.1.4.1.28308.1.5.0": ("DateAndTime", ""),
}




def save_state(state):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        print(f"[ERROR] No se pudo guardar mib_state.json: {e}")




def load_state():
    if not os.path.exists(STATE_FILE):
        save_state(DEFAULT_STORE)
        return DEFAULT_STORE.copy()
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except:
        save_state(DEFAULT_STORE)
        return DEFAULT_STORE.copy()




STORE = load_state()


# --------------------------------------------------------------------
# MOTOR SNMP — configuración de comunidades y permisos
# --------------------------------------------------------------------
snmp_engine = SnmpEngine()
snmpContext = context.SnmpContext(snmp_engine)


# Comunidad pública (solo lectura)
config.addV1System(snmp_engine, "public-area", "public")


# Comunidad privada (lectura y escritura)
config.addV1System(snmp_engine, "private-area", "private")


# Asignar vistas de acceso por modelo de seguridad (v1 y v2c)
for secModel in (1, 2):
    config.addVacmUser(
        snmp_engine,
        secModel,
        "public-area",
        "noAuthNoPriv",
        readSubTree=(1, 3, 6, 1)
    )
    config.addVacmUser(
        snmp_engine,
        secModel,
        "private-area",
        "noAuthNoPriv",
        readSubTree=(1, 3, 6, 1),
        writeSubTree=(1, 3, 6, 1)
    )


# Transporte UDP
config.addTransport(
    snmp_engine,
    udp.DOMAIN_NAME,
    udp.UdpTransport().openServerMode(("0.0.0.0", 1161))
)





# Configuración de destino de traps
config.addTargetParams(snmp_engine, "v2c-params", "public-area", "noAuthNoPriv", 2)
config.addTargetAddr(
    snmp_engine,
    "trap-dest-localhost",
    udp.DOMAIN_NAME,
    ("127.0.0.1", 162),
    "v2c-params",
    tagList="all-traps"
)
config.addNotificationTarget(snmp_engine, "public-area", "v2c-params", "all-traps", "trap")


# --------------------------------------------------------------------
# FUNCIONES AUXILIARES
# --------------------------------------------------------------------
CPU_OID = "1.3.6.1.4.1.28308.1.3.0"
THRESH_OID = "1.3.6.1.4.1.28308.1.4.0"
EMAIL_OID = "1.3.6.1.4.1.28308.1.2.0"
EVENTTIME_OID = "1.3.6.1.4.1.28308.1.5.0"


READ_ONLY_OIDS = {CPU_OID, EVENTTIME_OID}




def to_varbind(oid: str):
    try:
        t, v = STORE[oid]
        if t == "Integer32":
            return (v2c.ObjectIdentifier(oid), v2c.Integer(int(v)))
        elif t == "DateAndTime":
            return (v2c.ObjectIdentifier(oid), v2c.OctetString(v.encode("utf-8")))
        else:
            return (v2c.ObjectIdentifier(oid), v2c.OctetString(str(v)))
    except KeyError:
        return (v2c.ObjectIdentifier(oid), v2c.NoSuchObject())




def find_next_oid(oid_str: str):
    all_oids = sorted(STORE.keys())
    for o in all_oids:
        if o > oid_str:
            return o
    return None




# --------------------------------------------------------------------
# HANDLERS SNMP (GET / GETNEXT / SET)
# --------------------------------------------------------------------
class MiniGet(cmdrsp.GetCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        req = v2c.apiPDU.getVarBinds(PDU)
        rsp = [(oid, to_varbind(str(oid))[1]) if str(oid) in STORE else (oid, v2c.NoSuchObject()) for oid, _ in req]
        rsp_pdu = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setVarBinds(rsp_pdu, rsp)
        self.sendPdu(snmpEngine, stateReference, rsp_pdu)




class MiniGetNext(cmdrsp.NextCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        req = v2c.apiPDU.getVarBinds(PDU)
        rsp = []
        for oid, _ in req:
            next_oid = find_next_oid(str(oid))
            rsp.append(to_varbind(next_oid) if next_oid else (oid, v2c.EndOfMibView()))
        rsp_pdu = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setVarBinds(rsp_pdu, rsp)
        self.sendPdu(snmpEngine, stateReference, rsp_pdu)




class MiniSet(cmdrsp.SetCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        # --- Detección de comunidad (bloquea SET con public) ---
        try:
            exec_ctx = snmpEngine.observer.getExecutionContext("rfc3412.receiveMessage:request")
            sec_name = exec_ctx.get("securityName").prettyPrint() if exec_ctx else None
        except Exception:
            sec_name = None


        if sec_name == "public-area":
            rsp_pdu = v2c.apiPDU.getResponse(PDU)
            v2c.apiPDU.setErrorStatus(rsp_pdu, 17)
            v2c.apiPDU.setErrorIndex(rsp_pdu, 1)
            v2c.apiPDU.setVarBinds(rsp_pdu, v2c.apiPDU.getVarBinds(PDU))
            self.sendPdu(snmpEngine, stateReference, rsp_pdu)
            print("[DENEGADO] SET rechazado desde comunidad RO 'public'")
            return


        # --- Validaciones normales ---
        req = v2c.apiPDU.getVarBinds(PDU)
        rsp_pdu = v2c.apiPDU.getResponse(PDU)


        for idx, (oid, val) in enumerate(req, start=1):
            s = str(oid)


            if s not in STORE:
                v2c.apiPDU.setErrorStatus(rsp_pdu, 6)
                v2c.apiPDU.setErrorIndex(rsp_pdu, idx)
                v2c.apiPDU.setVarBinds(rsp_pdu, req)
                self.sendPdu(snmpEngine, stateReference, rsp_pdu)
                return


            if s in READ_ONLY_OIDS:
                v2c.apiPDU.setErrorStatus(rsp_pdu, 17)
                v2c.apiPDU.setErrorIndex(rsp_pdu, idx)
                v2c.apiPDU.setVarBinds(rsp_pdu, req)
                self.sendPdu(snmpEngine, stateReference, rsp_pdu)
                return


            t, _ = STORE[s]
            if (t == "Integer32" and not isinstance(val, v2c.Integer)) or \
               (t == "DisplayString" and not isinstance(val, v2c.OctetString)):
                v2c.apiPDU.setErrorStatus(rsp_pdu, 7)
                v2c.apiPDU.setErrorIndex(rsp_pdu, idx)
                v2c.apiPDU.setVarBinds(rsp_pdu, req)
                self.sendPdu(snmpEngine, stateReference, rsp_pdu)
                return


            if t == "DisplayString" and len(val.prettyPrint()) > 64:
                v2c.apiPDU.setErrorStatus(rsp_pdu, 10)
                v2c.apiPDU.setErrorIndex(rsp_pdu, idx)
                v2c.apiPDU.setVarBinds(rsp_pdu, req)
                self.sendPdu(snmpEngine, stateReference, rsp_pdu)
                return


            if t == "Integer32":
                intval = int(val)
                if intval < 0 or intval > 100:
                    v2c.apiPDU.setErrorStatus(rsp_pdu, 10)
                    v2c.apiPDU.setErrorIndex(rsp_pdu, idx)
                    v2c.apiPDU.setVarBinds(rsp_pdu, req)
                    self.sendPdu(snmpEngine, stateReference, rsp_pdu)
                    return


        rsp_varbinds = []
        for oid, val in req:
            s = str(oid)
            t, _ = STORE[s]
            if t == "Integer32":
                STORE[s] = (t, int(val))
            elif t == "DisplayString":
                STORE[s] = (t, val.prettyPrint())
            rsp_varbinds.append(to_varbind(s))


        save_state(STORE)
        v2c.apiPDU.setErrorStatus(rsp_pdu, 0)
        v2c.apiPDU.setErrorIndex(rsp_pdu, 0)
        v2c.apiPDU.setVarBinds(rsp_pdu, rsp_varbinds)
        self.sendPdu(snmpEngine, stateReference, rsp_pdu)




MiniGet(snmp_engine, snmpContext)
MiniGetNext(snmp_engine, snmpContext)
MiniSet(snmp_engine, snmpContext)


# --------------------------------------------------------------------
# MONITOR DE CPU + TRAP + EMAIL
# --------------------------------------------------------------------
async def cpu_monitor():
    psutil.cpu_percent(interval=None)
    last_over = False
    ntfOrg = ntforg.NotificationOriginator()


    while True:
        await asyncio.sleep(5)
        loop = asyncio.get_running_loop()
        cpu = int(psutil.cpu_percent(interval=None))
        thr = int(STORE[THRESH_OID][1])
        email = STORE[EMAIL_OID][1]
        over = cpu > thr


        STORE[CPU_OID] = ("Integer32", cpu)
        save_state(STORE)


        if over and not last_over:
            now = time.strftime("%Y-%m-%d,%H:%M:%S")
            STORE[EVENTTIME_OID] = ("DateAndTime", now)
            save_state(STORE)


            varBinds = [
                (v2c.ObjectIdentifier("1.3.6.1.6.3.1.1.4.1.0"), v2c.ObjectIdentifier("1.3.6.1.4.1.28308.2.1")),
                (v2c.ObjectIdentifier(CPU_OID), v2c.Integer(cpu)),
                (v2c.ObjectIdentifier(THRESH_OID), v2c.Integer(thr)),
                (v2c.ObjectIdentifier(EMAIL_OID), v2c.OctetString(email)),
                (v2c.ObjectIdentifier(EVENTTIME_OID), v2c.OctetString(now.encode("utf-8"))),
            ]


            try:
                await loop.run_in_executor(None, ntfOrg.sendVarBinds, snmp_engine, "public-area", None, "trap", varBinds)
                print(f"[TRAP] CPU={cpu}% > {thr}% - Trap enviado, eventTime={now}")
            except Exception as e:
                print(f"[ERROR] Fallo al enviar TRAP: {e}")


            if ENABLE_EMAIL:
                subject = f"Alerta SNMP: CPU {cpu}% > {thr}%"
                body = f"{cpu}%|{thr}%|{now}"
                try:
                    await loop.run_in_executor(None, send_email_gmail, email, subject, body)
                except Exception as e:
                    print(f"[ERROR] Fallo al enviar correo: {e}")


        last_over = over




# --------------------------------------------------------------------
# MAIN LOOP
# --------------------------------------------------------------------
def main():
    print("Mini SNMP Agent (pysnmp 7.1.4)")
    print("Escuchando en UDP/1161 (comunidades: public/private)")


    loop = asyncio.get_event_loop()
    loop.create_task(cpu_monitor())


    try:
        snmp_engine.transportDispatcher.jobStarted(1)
        loop.run_forever()
    except KeyboardInterrupt:
        print("Cerrando agente...")
    finally:
        print("Agente cerrado.")




if __name__ == "__main__":
    main()


