"""
alertas/gestor_alertas.py
Sistema de alertas con scoring 0-100 y niveles de riesgo.
POO: Encapsulamiento de la lógica de negocio de alertas.
"""
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from core.paquete import Paquete


class NivelRiesgo(Enum):
    BAJO    = ("BAJO",    "🟢", 0,  "#10b981")
    MEDIO   = ("MEDIO",   "🟡", 1,  "#f59e0b")
    ALTO    = ("ALTO",    "🟠", 2,  "#f97316")
    CRITICO = ("CRÍTICO", "🔴", 3,  "#ef4444")

    def __init__(self, etiqueta, icono, prioridad, color_hex):
        self.etiqueta  = etiqueta
        self.icono     = icono
        self.prioridad = prioridad
        self.color     = color_hex

    def __str__(self):
        return f"{self.icono} {self.etiqueta}"


@dataclass
class Alerta:
    """Representa una amenaza detectada por el IDS."""
    paquete:        Paquete
    tipo_ataque:    str
    confianza:      float
    score:          int           # 0 – 100
    nivel:          NivelRiesgo
    accion:         str
    modelo_origen:  str
    timestamp:      datetime = field(default_factory=datetime.now)
    atendida:       bool     = False

    def to_dict(self) -> dict:
        return {
            "timestamp":     self.timestamp.isoformat(),
            "nivel":         self.nivel.etiqueta,
            "nivel_icono":   self.nivel.icono,
            "nivel_color":   self.nivel.color,
            "tipo_ataque":   self.tipo_ataque,
            "score":         self.score,
            "confianza":     self.confianza,
            "ip_origen":     self.paquete.ip_origen,
            "ip_destino":    self.paquete.ip_destino,
            "protocolo":     self.paquete.protocolo,
            "puerto_dst":    self.paquete.puerto_dst,
            "accion":        self.accion,
            "modelo_origen": self.modelo_origen,
            "atendida":      self.atendida,
        }

    def __str__(self) -> str:
        return (f"[{self.timestamp:%H:%M:%S}] {self.nivel}  "
                f"| {self.tipo_ataque.upper():12s} "
                f"| score={self.score:3d} "
                f"| {self.paquete.ip_origen} → {self.paquete.ip_destino} "
                f"| {self.accion}")


class GestorAlertas:
    """
    Crea, prioriza y almacena alertas.
    Aplica scoring 0-100 basado en tipo de ataque × confianza del modelo.
    """

    _PESOS = {
        "normal":     0,
        "anomalia":   50,
        "portscan":   55,
        "bruteforce": 78,
        "dos":        85,
        "mitm":       95,
    }

    def __init__(self):
        self._historial: list = []

    def calcular_score(self, tipo: str, confianza: float) -> int:
        peso = self._PESOS.get(tipo, 50)
        return min(100, int(peso * confianza))

    def _determinar_nivel(self, score: int) -> tuple:
        if score >= 80:
            return NivelRiesgo.CRITICO, "🚨 Bloquear IP + Notificar administrador urgente"
        elif score >= 60:
            return NivelRiesgo.ALTO,    "⚠️  Notificar administrador por email/SMS"
        elif score >= 35:
            return NivelRiesgo.MEDIO,   "📋 Registrar y monitorear de cerca"
        else:
            return NivelRiesgo.BAJO,    "📝 Solo registrar en log"

    def crear_alerta(self, paquete: Paquete, resultado_ia: dict):
        """Crea alerta si es amenaza. Retorna Alerta o None."""
        if not resultado_ia.get("es_amenaza", False):
            return None

        tipo  = resultado_ia["etiqueta"]
        conf  = resultado_ia["confianza"]
        score = self.calcular_score(tipo, conf)
        nivel, accion = self._determinar_nivel(score)

        alerta = Alerta(
            paquete       = paquete,
            tipo_ataque   = tipo,
            confianza     = conf,
            score         = score,
            nivel         = nivel,
            accion        = accion,
            modelo_origen = resultado_ia.get("modelo_ganador",
                                             resultado_ia.get("modelo", "?")),
        )
        self._historial.append(alerta)
        return alerta

    def todas(self) -> list:
        return self._historial

    def criticas(self) -> list:
        return [a for a in self._historial if a.nivel == NivelRiesgo.CRITICO]

    def por_tipo(self) -> dict:
        conteo = {}
        for a in self._historial:
            conteo[a.tipo_ataque] = conteo.get(a.tipo_ataque, 0) + 1
        return conteo

    def ips_mas_frecuentes(self, top: int = 5) -> list:
        from collections import Counter
        c = Counter(a.paquete.ip_origen for a in self._historial)
        return c.most_common(top)

    def resumen(self) -> dict:
        total = len(self._historial)
        return {
            "total":    total,
            "criticas": sum(1 for a in self._historial if a.nivel == NivelRiesgo.CRITICO),
            "altas":    sum(1 for a in self._historial if a.nivel == NivelRiesgo.ALTO),
            "medias":   sum(1 for a in self._historial if a.nivel == NivelRiesgo.MEDIO),
            "bajas":    sum(1 for a in self._historial if a.nivel == NivelRiesgo.BAJO),
        }
