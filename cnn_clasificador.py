"""
modelos/detector_base.py
Clase abstracta base para todos los detectores de IA.
POO: Abstracción — define el contrato sin implementar lógica concreta.
"""
from abc import ABC, abstractmethod
from core.paquete import Paquete


class DetectorBase(ABC):
    """
    Contrato común para cualquier modelo de detección.
    Permite intercambiar RF, CNN, Autoencoder sin cambiar el resto del sistema.
    """
    TIPOS_ATAQUE = ["normal", "dos", "portscan", "bruteforce", "mitm"]

    def __init__(self, nombre: str):
        self.nombre    = nombre
        self.entrenado = False
        self.metricas  = {}

    @abstractmethod
    def entrenar(self, paquetes: list, etiquetas: list) -> dict:
        """Entrena el modelo. Retorna métricas {'accuracy': float, ...}"""
        pass

    @abstractmethod
    def predecir(self, paquete: Paquete) -> dict:
        """
        Retorna:
        {
          'etiqueta':   str,
          'confianza':  float,   # 0.0 – 1.0
          'es_amenaza': bool,
          'modelo':     str,
        }
        """
        pass

    def predecir_lote(self, paquetes: list) -> list:
        """Predice sobre una lista de paquetes."""
        return [self.predecir(p) for p in paquetes]

    def __str__(self) -> str:
        estado = "✅ entrenado" if self.entrenado else "⏳ sin entrenar"
        return f"[{self.nombre}] {estado}"
