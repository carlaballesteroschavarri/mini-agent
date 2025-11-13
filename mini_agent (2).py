import asyncio
import psutil
import time
import json
import os

from pysnmp.hlapi.v3arch.asyncio import *
from pysnmp.proto.api import v2c
from pysnmp.entity import config
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity.rfc3413 import cmdrsp, ntforg, context

# --------------------------------------------------------------------
# PERSISTENCIA DEL ESTADO (mib_state.json)
# --------------------------------------------------------------------
STATE_FILE = "mib_state.json"

# Estado por defecto si no hay JSON
DEFAULT_STORE = {
    "1.3.6.1.4.1.28308.1.1.0": ("DisplayString", "Admin"),
    "1.3.6.1.4.1.28308.1.2.0": ("DisplayString", "873300@unizar.es"),
    "1.3.6.1.4.1.28308.1.3.0": ("Integer32", 0),      # cpuUsage
    "1.3.6.1.4.1.28308.1.4.0": ("Integer32", 20),     # cpuThreshold
    "1.3.6.1.4.1.28308.1.5.0": ("DisplayString", ""), # eventTime
}


def save_state(state):
    """Guarda el estado actual en mib_state.json."""
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
        print("[INFO] mib_state.json actualizado.")
    except Exception as e:
        print(f"[ERROR] No se pudo guardar mib_state.json: {e}")


def load_state():
    """Carga mib_state.json o crea uno nuevo con valores por defecto."""
    if not os.path.exists(STATE_FILE):
        print("[INFO] mib_state.json no existe, creando con valores por defecto.")
        save_state(DEFAULT_STORE)
        return DEFAULT_STORE.copy()

    try:
        with open(STATE_FILE, "r") as f:
            data = json.load(f)
        print("[INFO] mib_state.json cargado correctamente.")
        return data
    except Exception as e:
        print(f"[WARN] Error leyendo mib_state.json ({e}), usando DEFAULT_STORE.")
        save_state(DEFAULT_STORE)
        return DEFAULT_STORE.copy()


# Diccionario global con el estado de la MIB
STORE = load_state()

# --------------------------------------------------------------------
# MOTOR SNMP
# --------------------------------------------------------------------
snmp_engine = SnmpEngine()
snmpContext = context.SnmpContext(snmp_engine)

# Comunidades (public RO, private RW)
config.addV1System(snmp_engine, 'public-area', 'public')
config.addV1System(snmp_engine, 'private-area', 'private')

# Control de acceso VACM
for secModel in (1, 2):  # SNMPv1 y SNMPv2c
    config.addVacmUser(
        snmp_engine, secModel, 'public-area', 'noAuthNoPriv',
        readSubTree=(1, 3, 6, 1)
    )
    config.addVacmUser(
        snmp_engine, secModel, 'private-area', 'noAuthNoPriv',
        readSubTree=(1, 3, 6, 1),
        writeSubTree=(1, 3, 6, 1)
    )

# Transporte UDP en puerto 1161 (cámbialo a 161 si quieres y tienes permisos)
config.addTransport(
    snmp_engine,
    udp.domainName,
    udp.UdpTransport().openServerMode(('0.0.0.0', 1161))
)

# --------------------------------------------------------------------
# FUNCIONES AUXILIARES
# --------------------------------------------------------------------
CPU_OID = "1.3.6.1.4.1.28308.1.3.0"
EVENTTIME_OID = "1.3.6.1.4.1.28308.1.5.0"


def to_varbind(oid: str):
    """
    Convierte un OID de nuestro STORE en un varBind SNMP.
    Para cpuUsage, actualiza primero con el valor REAL medido.
    """
    # Actualizar medición de CPU "en tiempo real" si es el OID de cpuUsage
    if oid == CPU_OID:
        cpu_percent = int(psutil.cpu_percent(interval=None))
        STORE[oid] = ("Integer32", cpu_percent)
        save_state(STORE)

    t, v = STORE[oid]  # t = tipo, v = valor (lista o tupla, da igual)
    if t == "Integer32":
        return (v2c.ObjectIdentifier(oid), v2c.Integer(int(v)))
    else:
        return (v2c.ObjectIdentifier(oid), v2c.OctetString(str(v)))


def find_next_oid(oid_str: str):
    """Encuentra el siguiente OID lexicográfico dentro de STORE."""
    all_oids = sorted(STORE.keys())
    for o in all_oids:
        if o > oid_str:
            return o
    return None


# --------------------------------------------------------------------
# RESPONDER SNMP GET/GETNEXT/SET
# --------------------------------------------------------------------
class MiniGet(cmdrsp.GetCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        req = v2c.apiPDU.getVarBinds(PDU)
        rsp = []
        for oid, _ in req:
            s = str(oid)
            if s in STORE:
                rsp.append(to_varbind(s))
            else:
                rsp.append((oid, v2c.NoSuchObject()))
        rsp_pdu = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setVarBinds(rsp_pdu, rsp)
        self.sendPdu(snmpEngine, stateReference, rsp_pdu)


class MiniGetNext(cmdrsp.NextCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        req = v2c.apiPDU.getVarBinds(PDU)
        rsp = []
        for oid, _ in req:
            next_oid = find_next_oid(str(oid))
            if next_oid:
                rsp.append(to_varbind(next_oid))
            else:
                rsp.append((oid, v2c.EndOfMibView()))
        rsp_pdu = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setVarBinds(rsp_pdu, rsp)
        self.sendPdu(snmpEngine, stateReference, rsp_pdu)


class MiniSet(cmdrsp.SetCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        req = v2c.apiPDU.getVarBinds(PDU)
        rsp = []
        for oid, val in req:
            s = str(oid)
            if s not in STORE:
                rsp.append((oid, v2c.NoSuchObject()))
                continue

            t, _ = STORE[s]

            # Validaciones simples de tipo
            if t == "Integer32" and isinstance(val, v2c.Integer):
                STORE[s] = (t, int(val))
            elif t == "DisplayString" and isinstance(val, v2c.OctetString):
                STORE[s] = (t, val.prettyPrint())
            else:
                # Tipo incorrecto → wrongType/wrongValue, pero para simplificar
                rsp.append((oid, v2c.NoSuchObject()))
                continue

            rsp.append(to_varbind(s))

        # Guardar después de aplicar los SET
        save_state(STORE)

        rsp_pdu = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setVarBinds(rsp_pdu, rsp)
        self.sendPdu(snmpEngine, stateReference, rsp_pdu)


# Registrar los responders
MiniGet(snmp_engine, snmpContext)
MiniGetNext(snmp_engine, snmpContext)
MiniSet(snmp_engine, snmpContext)

# --------------------------------------------------------------------
# MONITOR CPU Y ENVÍO DE TRAP
# --------------------------------------------------------------------
async def cpu_monitor():
    """
    Tarea periódica que:
      - actualiza cpuUsage en STORE
      - dispara un TRAP cuando cpuUsage cruza el umbral cpuThreshold (por flanco)
      - actualiza eventTime cuando ocurre el evento
      - guarda en mib_state.json
    """
    psutil.cpu_percent(interval=None)
    last_over = False

    while True:
        await asyncio.sleep(5)

        cpu = int(psutil.cpu_percent(interval=None))
        STORE[CPU_OID] = ("Integer32", cpu)

        thr = int(STORE["1.3.6.1.4.1.28308.1.4.0"][1])  # cpuThreshold
        email = STORE["1.3.6.1.4.1.28308.1.2.0"][1]     # managerEmail
        over = cpu > thr

        # Guardamos la nueva medida de CPU
        save_state(STORE)

        if over and not last_over:
            now = time.strftime("%Y-%m-%d,%H:%M:%S")
            STORE[EVENTTIME_OID] = ("DisplayString", now)
            save_state(STORE)

            varBinds = [
                (v2c.ObjectIdentifier("1.3.6.1.6.3.1.1.4.1.0"),
                 v2c.ObjectIdentifier("1.3.6.1.4.1.28308.2.1")),
                (v2c.ObjectIdentifier("1.3.6.1.4.1.28308.1.3.0"), v2c.Integer(cpu)),
                (v2c.ObjectIdentifier("1.3.6.1.4.1.28308.1.4.0"), v2c.Integer(thr)),
                (v2c.ObjectIdentifier("1.3.6.1.4.1.28308.1.2.0"), v2c.OctetString(email)),
                (v2c.ObjectIdentifier("1.3.6.1.4.1.28308.1.5.0"), v2c.OctetString(now)),
            ]

            ntfOrg = ntforg.NotificationOriginator()
            ntfOrg.sendNotification(
                snmp_engine,
                "public-area",   # usamos la comunidad public-area
                None,
                "trap",
                varBinds=varBinds,
            )
            print(f"[TRAP] CPU={cpu}% > {thr}% - Trap enviado")

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
        snmp_engine.transportDispatcher.runDispatcher()
    except KeyboardInterrupt:
        print("Cerrando agente...")
    finally:
        snmp_engine.transportDispatcher.closeDispatcher()
        loop.stop()


if __name__ == "__main__":
    main()
