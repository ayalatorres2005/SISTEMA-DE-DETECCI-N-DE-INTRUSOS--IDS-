"""
core/sniffer.py
Captura y filtrado de paquetes.
POO: Abstracción (CapturadorBase) + Herencia + Polimorfismo
"""
from abc import ABC, abstractmethod
from core.paquete import Paquete
from datetime import datetime
import random


class CapturadorBase(ABC):
    """Clase abstracta: contrato para todos los capturadores de tráfico."""

    def __init__(self, lista_negra: list = None):
        self._lista_negra: list = lista_negra or []
        self._total_capturados: int = 0

    @abstractmethod
    def capturar(self, cantidad: int) -> list:
        pass

    @abstractmethod
    def filtrar(self, paquetes: list) -> list:
        pass

    def agregar_ip_bloqueada(self, ip: str) -> None:
        if ip not in self._lista_negra:
            self._lista_negra.append(ip)
            print(f"  [FIREWALL] IP bloqueada: {ip}")

    def total_capturados(self) -> int:
        return self._total_capturados


# ── SNIFFER REAL (Scapy) ────────────────────────────────────────────────────
class Sniffer(CapturadorBase):
    """Captura paquetes reales con Scapy. Requiere privilegios root."""

    def __init__(self, interfaz: str = "eth0", lista_negra: list = None):
        super().__init__(lista_negra)
        self.interfaz = interfaz

    def capturar(self, cantidad: int = 100) -> list:
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP
            raw = sniff(iface=self.interfaz, count=cantidad, timeout=15)
            paquetes = []
            for p in raw:
                if IP in p:
                    proto = ("TCP"  if TCP  in p else
                             "UDP"  if UDP  in p else
                             "ICMP" if ICMP in p else "OTRO")
                    pkt = Paquete(
                        ip_origen  = p["IP"].src,
                        ip_destino = p["IP"].dst,
                        protocolo  = proto,
                        tamanio    = len(p),
                        puerto_src = int(p["TCP"].sport) if TCP in p else
                                     int(p["UDP"].sport) if UDP in p else 0,
                        puerto_dst = int(p["TCP"].dport) if TCP in p else
                                     int(p["UDP"].dport) if UDP in p else 0,
                        payload    = bytes(p),
                    )
                    paquetes.append(pkt)
            self._total_capturados += len(paquetes)
            return paquetes
        except ImportError:
            print("[AVISO] Scapy no disponible. Usa SnifferSimulado para pruebas.")
            return []

    def filtrar(self, paquetes: list) -> list:
        return [p for p in paquetes if p.ip_origen not in self._lista_negra]


# ── SNIFFER SIMULADO (sin hardware, sin root) ───────────────────────────────
class SnifferSimulado(CapturadorBase):
    """
    Genera tráfico ficticio para pruebas y demos.
    Mismo contrato que Sniffer → Polimorfismo.
    """

    _PROTOCOLOS   = ["TCP", "UDP", "ICMP", "TCP", "TCP"]
    _IPS_EXTERNAS = [
        "192.168.1.10", "10.0.0.5",    "172.16.0.20",
        "203.0.113.4",  "198.51.100.7","192.0.2.1",
        "45.33.32.156", "185.220.101.5","104.21.0.1",
    ]
    # (protocolo, puerto_dst, tamanio_min, tamanio_max, etiqueta_real)
    _PATRONES_ATAQUE = [
        ("TCP",  22,   40,  120,  "bruteforce"),
        ("TCP",  22,   40,   80,  "bruteforce"),
        ("TCP",  21,   40,  100,  "portscan"),
        ("TCP",  23,   40,   80,  "portscan"),
        ("TCP",  3306, 40,   90,  "portscan"),
        ("UDP",   0, 1300, 1500,  "dos"),
        ("ICMP",  0,  900, 1500,  "dos"),
        ("TCP",  80, 1300, 1500,  "dos"),
        ("TCP", 443,  200,  500,  "normal"),
        ("UDP",  53,   60,  150,  "normal"),
        ("TCP",  80,   200, 800,  "normal"),
        ("TCP", 8080,  300, 900,  "normal"),
        ("TCP", 443,   100, 400,  "normal"),
    ]

    def __init__(self, lista_negra: list = None, semilla: int = 42):
        super().__init__(lista_negra)
        random.seed(semilla)
        self._semilla = semilla

    def capturar(self, cantidad: int = 50) -> list:
        paquetes = []
        for _ in range(cantidad):
            patron = random.choice(self._PATRONES_ATAQUE)
            proto, pdst, tmin, tmax, _ = patron
            pkt = Paquete(
                ip_origen  = random.choice(self._IPS_EXTERNAS),
                ip_destino = f"10.0.{random.randint(0,5)}.{random.randint(1,254)}",
                protocolo  = proto,
                tamanio    = random.randint(tmin, tmax),
                puerto_src = random.randint(1024, 65535),
                puerto_dst = pdst if pdst else random.randint(1, 65535),
                payload    = b"\x00" * random.randint(0, 50),
                timestamp  = datetime.now(),
            )
            paquetes.append(pkt)
        self._total_capturados += len(paquetes)
        return paquetes

    def filtrar(self, paquetes: list) -> list:
        return [p for p in paquetes
                if p.ip_origen not in self._lista_negra and p.tamanio >= 40]

    def generar_con_etiquetas(self, cantidad: int = 200) -> tuple:
        """Genera paquetes CON etiquetas reales para entrenar modelos IA."""
        random.seed(self._semilla)
        paquetes, etiquetas = [], []
        for _ in range(cantidad):
            patron = random.choice(self._PATRONES_ATAQUE)
            proto, pdst, tmin, tmax, etiq = patron
            pkt = Paquete(
                ip_origen  = random.choice(self._IPS_EXTERNAS),
                ip_destino = f"10.0.{random.randint(0,5)}.{random.randint(1,254)}",
                protocolo  = proto,
                tamanio    = random.randint(tmin, tmax),
                puerto_src = random.randint(1024, 65535),
                puerto_dst = pdst if pdst else random.randint(1, 65535),
            )
            paquetes.append(pkt)
            etiquetas.append(etiq)
        return paquetes, etiquetas
