#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de pruebas automáticas para el Mini SNMP Agent
"""

import subprocess
import time
import os
import json
from colorama import Fore, Style, init
from prettytable import PrettyTable

# Inicializar colorama
init(autoreset=True)

# ===== CONFIGURACIÓN =====
HOST = "127.0.0.1:1161"
COMM_RO = "public"
COMM_RW = "private"

BASE_OID = "1.3.6.1.4.1.28308.1"
OIDS = {
    "manager": f"{BASE_OID}.1.0",
    "managerEmail": f"{BASE_OID}.2.0",
    "cpuUsage": f"{BASE_OID}.3.0",
    "cpuThreshold": f"{BASE_OID}.4.0",
    "eventTime": f"{BASE_OID}.5.0",
}

STATE_FILE = os.path.join(os.path.dirname(__file__), "mib_state.json")

summary = []


def run_cmd(desc, cmd, expect_error=None, timeout=6):
    print(Fore.CYAN + f"\n🔹 {desc}")
    print(Fore.WHITE + "Comando:", Fore.YELLOW + cmd)
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        out = (result.stdout or "") + (result.stderr or "")
        out = out.strip()

        if not out:
            print(Fore.RED + "❌ Sin respuesta del agente SNMP (timeout).")
            return "NO RESPONSE"

        if expect_error:
            if expect_error.lower() in out.lower():
                print(Fore.GREEN + f"✅ Error esperado detectado → {expect_error}")
                return "OK"
            else:
                print(Fore.RED + f"❌ Se esperaba '{expect_error}', pero se recibió:")
                print(Fore.WHITE + out)
                return "FAIL"
        else:
            print(Fore.GREEN + "✅ Respuesta OK:")
            print(Fore.WHITE + out)
            return "OK"
    except Exception as e:
        print(Fore.RED + f"⚠️ Error al ejecutar comando: {e}")
        return "ERROR"


def snmpget_value(oid, community=COMM_RW):
    cmd = f"snmpget -v2c -c {community} {HOST} {oid}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        out = (result.stdout or "") + (result.stderr or "")
        out = out.strip()
        if " = " not in out:
            return None
        value_part = out.split(" = ", 1)[1].strip()
        if ": " in value_part:
            value_part = value_part.split(": ", 1)[1].strip()

        # quitar comillas envolventes para comparar con el JSON
        if value_part.startswith('"') and value_part.endswith('"'):
            value_part = value_part[1:-1]

        return value_part
    except Exception:
        return None


def check_json_state():
    print(Fore.CYAN + "\n🔹 Comprobando persistencia en mib_state.json usando OID reales...")
    if not os.path.exists(STATE_FILE):
        print(Fore.YELLOW + "⚠️ No se encontró mib_state.json, quizá el agente aún no lo ha creado.")
        summary.append(["Persistencia (json)", "Persistencia", "WARN"])
        return

    try:
        with open(STATE_FILE, "r") as f:
            data = json.load(f)
    except Exception as e:
        print(Fore.RED + f"❌ No se pudo leer mib_state.json: {e}")
        summary.append(["Persistencia (json)", "Persistencia", "ERROR"])
        return

    for name, oid in OIDS.items():
        json_entry = data.get(oid)
        agent_val = snmpget_value(oid, community=COMM_RW)

        if json_entry is None:
            print(Fore.RED + f"❌ En el JSON no aparece el OID {oid} ({name})")
            summary.append([f"JSON {name}", "Persistencia", "FAIL"])
            continue

        if isinstance(json_entry, (list, tuple)) and len(json_entry) == 2:
            json_type, json_val = json_entry
        else:
            json_type, json_val = ("?", json_entry)

        json_val_str = str(json_val)
        agent_val_str = str(agent_val) if agent_val is not None else None

        print(Fore.WHITE + f"OID {oid} ({name}) → JSON=({json_type}, {json_val_str}) ; Agente={agent_val_str}")

        if agent_val_str is not None and agent_val_str == json_val_str:
            summary.append([f"JSON {name}", "Persistencia", "OK"])
        else:
            summary.append([f"JSON {name}", "Persistencia", "WARN"])

    print(Fore.GREEN + "✅ Comprobación de JSON terminada.")


def test_access():
    print(Fore.MAGENTA + Style.BRIGHT + "\n🚀 INICIO DE PRUEBAS DEL MINI SNMP AGENT (extendido) 🚀\n")
    time.sleep(1)

    # 1) GET de todos los scalars con public
    for name, oid in OIDS.items():
        summary.append([f"GET {name} (public)", "Lectura", run_cmd(
            f"GET {name} con comunidad public",
            f"snmpget -v2c -c {COMM_RO} {HOST} {oid}"
        )])

    # 2) SET con public debe fallar
    summary.append(["SET manager (public)", "Error notWritable", run_cmd(
        "SET manager usando comunidad de solo lectura (public)",
        f"snmpset -v2c -c {COMM_RO} {HOST} {OIDS['manager']} s \"NoDeberia\"",
        expect_error="notWritable"
    )])

    # 3) SET válidos con private
    summary.append(["SET manager (private)", "Escritura", run_cmd(
        "SET manager con comunidad private",
        f"snmpset -v2c -c {COMM_RW} {HOST} {OIDS['manager']} s \"CarlayArancha\""
    )])

    summary.append(["SET managerEmail (private)", "Escritura", run_cmd(
        "SET managerEmail con comunidad private",
        f"snmpset -v2c -c {COMM_RW} {HOST} {OIDS['managerEmail']} s \"carla.ballesteros64@gmail.com\""
    )])

    original_thr = snmpget_value(OIDS["cpuThreshold"], community=COMM_RW)
    try:
        original_thr_int = int(original_thr)
    except (TypeError, ValueError):
        original_thr_int = 20

    summary.append(["SET cpuThreshold (private)", "Escritura", run_cmd(
        "SET cpuThreshold a 50 con comunidad private",
        f"snmpset -v2c -c {COMM_RW} {HOST} {OIDS['cpuThreshold']} i 50"
    )])

    # 4) SET sobre RO
    summary.append(["SET cpuUsage (private)", "Error notWritable", run_cmd(
        "SET sobre objeto de solo lectura (cpuUsage)",
        f"snmpset -v2c -c {COMM_RW} {HOST} {OIDS['cpuUsage']} i 10",
        expect_error="notWritable"
    )])

    # 5) Tipo incorrecto
    summary.append(["SET cpuThreshold tipo incorrecto", "Error wrongType", run_cmd(
        "SET cpuThreshold con tipo incorrecto (string en lugar de int)",
        f"snmpset -v2c -c {COMM_RW} {HOST} {OIDS['cpuThreshold']} s \"bad-type\"",
        expect_error="wrongType"
    )])

    # 6) Valor fuera de rango
    summary.append(["SET cpuThreshold fuera de rango", "Error wrongValue", run_cmd(
        "SET cpuThreshold fuera de rango (>100)",
        f"snmpset -v2c -c {COMM_RW} {HOST} {OIDS['cpuThreshold']} i 200",
        expect_error="wrongValue"
    )])

    # 7) OID inexistente
    summary.append(["SET OID inexistente", "Error noAccess", run_cmd(
        "SET sobre OID inexistente",
        f"snmpset -v2c -c {COMM_RW} {HOST} 1.3.6.1.4.1.28308.99.0 i 10",
        expect_error="noAccess"
    )])

    # 8) GETNEXT
    summary.append(["GETNEXT (public)", "Recorrido", run_cmd(
        "GETNEXT lexicográfico (public)",
        f"snmpgetnext -v2c -c {COMM_RO} {HOST} {BASE_OID}.1.0"
    )])

    # 9) SNMPWALK
    summary.append(["SNMPWALK (public)", "Recorrido", run_cmd(
        "snmpwalk del subárbol del agente",
        f"snmpwalk -v2c -c {COMM_RO} {HOST} {BASE_OID}"
    )])

    # 10) Comprobar JSON por OID
    check_json_state()

    # 11) Comprobar actualización periódica de cpuUsage MOSTRANDO valores
    print(Fore.CYAN + "\n🔹 Comprobando actualización periódica de cpuUsage (3 lecturas cada 5s)...")
    cpu_values = []
    for i in range(3):
        val = snmpget_value(OIDS["cpuUsage"], community=COMM_RO)
        cpu_values.append(val)
        print(Fore.WHITE + f"Lectura {i+1}: cpuUsage = {val}")
        if i < 2:
            time.sleep(5)

    # comprobar si alguna lectura cambió
    if len(set(cpu_values)) > 1 and None not in cpu_values:
        print(Fore.GREEN + "✅ cpuUsage cambia con el tiempo.")
        summary.append(["Actualización cpuUsage", "Dinámico", "OK"])
    else:
        print(Fore.YELLOW + "⚠️ cpuUsage no cambió en las lecturas (o alguna fue None).")
        summary.append(["Actualización cpuUsage", "Dinámico", "WARN"])

    # 12) Forzar alerta
    print(Fore.CYAN + "\n🔹 Forzando alerta de CPU para que el agente actualice eventTime...")
    run_cmd("Bajar cpuThreshold a 0 para forzar alerta", f"snmpset -v2c -c {COMM_RW} {HOST} {OIDS['cpuThreshold']} i 0")
    time.sleep(7)
    ev = snmpget_value(OIDS["eventTime"], community=COMM_RO)
    if ev and ev != '""':
        print(Fore.GREEN + f"✅ eventTime actualizado → {ev}")
        summary.append(["Alerta CPU (eventTime)", "Trap/email", "OK"])
    else:
        print(Fore.YELLOW + "⚠️ eventTime sigue vacío.")
        summary.append(["Alerta CPU (eventTime)", "Trap/email", "WARN"])

    # restaurar umbral
    run_cmd("Restaurar cpuThreshold al valor original", f"snmpset -v2c -c {COMM_RW} {HOST} {OIDS['cpuThreshold']} i {original_thr_int}")

    # RESUMEN
    print(Fore.MAGENTA + Style.BRIGHT + "\n📋 RESUMEN FINAL DE PRUEBAS 📋\n")
    table = PrettyTable()
    table.field_names = ["Prueba", "Tipo", "Resultado"]

    for test, ttype, res in summary:
        color = Fore.GREEN if res == "OK" else Fore.RED if res == "FAIL" else Fore.YELLOW
        table.add_row([test, ttype, color + res + Style.RESET_ALL])

    print(table)
    print(Fore.CYAN + Style.BRIGHT + "\n✅ VALIDACIÓN COMPLETA.\n")


if __name__ == "__main__":
    test_access()
