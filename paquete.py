"""
core/paquete.py
Entidad central: representa un paquete de red capturado.
POO: Encapsulamiento de todos los datos de red en un objeto cohesivo.
"""
from datetime import datetime
from dataclasses import dataclass, field


@dataclass
class Paquete:
    """
    Unidad de datos que fluye por todo el sistema IDS.
    Contiene datos crudos de red + resultados del análisis de IA.
    """
    ip_origen:      str
    ip_destino:     str
    protocolo:      str          # TCP | UDP | ICMP | OTRO
    tamanio:        int          # bytes
    puerto_src:     int   = 0
    puerto_dst:     int   = 0
    payload:        bytes = field(default_factory=bytes, repr=False)
    timestamp:      datetime = field(default_factory=datetime.now)

    # Llenados por la capa de IA tras el análisis
    etiqueta:       str   = "sin_clasificar"
    score_riesgo:   float = 0.0    # confianza del modelo RF/CNN  (0-1)
    anomalia_score: float = 0.0    # error de reconstrucción del Autoencoder

    def es_sospechoso(self, umbral: float = 0.4) -> bool:
        return self.score_riesgo >= umbral or self.anomalia_score >= 0.6

    def to_dict(self) -> dict:
        return {
            "timestamp":      self.timestamp.isoformat(),
            "ip_origen":      self.ip_origen,
            "ip_destino":     self.ip_destino,
            "protocolo":      self.protocolo,
            "tamanio":        self.tamanio,
            "puerto_src":     self.puerto_src,
            "puerto_dst":     self.puerto_dst,
            "etiqueta":       self.etiqueta,
            "score_riesgo":   round(self.score_riesgo,   4),
            "anomalia_score": round(self.anomalia_score, 4),
        }

    def to_features(self) -> list:
        """Vector numérico para los modelos de IA."""
        proto_map = {"TCP": 0.0, "UDP": 1.0, "ICMP": 2.0, "OTRO": 3.0}
        return [
            proto_map.get(self.protocolo, 3.0),
            float(self.tamanio),
            float(self.puerto_src),
            float(self.puerto_dst),
            float(hash(self.ip_origen)  % 10_000),
            float(hash(self.ip_destino) % 10_000),
        ]

    def __str__(self) -> str:
        return (f"[{self.timestamp:%H:%M:%S}] "
                f"{self.ip_origen}:{self.puerto_src} → "
                f"{self.ip_destino}:{self.puerto_dst} "
                f"({self.protocolo}) {self.tamanio}B "
                f"etiq={self.etiqueta} score={self.score_riesgo:.2f}")

