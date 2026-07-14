"""
modelos/motor_ia.py
Motor de IA que orquesta los tres modelos: RF + Autoencoder + CNN.
Aplica votación por ensemble para mayor precisión.
POO: Composición — contiene instancias de los tres detectores.
"""
from core.paquete import Paquete
from modelos.random_forest    import DetectorRandomForest
from modelos.autoencoder      import AutoencoderDetector
from modelos.cnn_clasificador import CNNClasificador


class MotorIA:
    """
    Orquestador de los modelos de IA del IDS.
    Combina RF + CNN (clasificación) + Autoencoder (anomalía)
    mediante un esquema de votación ponderada.

    El parámetro usar_tensorflow permite degradar a solo Random Forest
    si TensorFlow no está instalado (failsafe).
    """

    def __init__(self, usar_tensorflow: bool = True):
        self.rf          = DetectorRandomForest(n_arboles=150)
        self._usar_tf    = usar_tensorflow
        self.autoencoder = AutoencoderDetector() if usar_tensorflow else None
        self.cnn         = CNNClasificador()     if usar_tensorflow else None
        self._entrenado  = False
        self.metricas    = {}

    def entrenar(self, paquetes: list, etiquetas: list) -> dict:
        """Entrena los modelos disponibles con el mismo conjunto de datos."""
        print("\n  📦 Entrenando Random Forest...")
        m_rf = self.rf.entrenar(paquetes, etiquetas)
        self.metricas["random_forest"] = m_rf

        if self._usar_tf and self.autoencoder:
            print("  📦 Entrenando Autoencoder...")
            self.metricas["autoencoder"] = self.autoencoder.entrenar(paquetes, etiquetas)

        if self._usar_tf and self.cnn:
            print("  📦 Entrenando CNN...")
            self.metricas["cnn"] = self.cnn.entrenar(paquetes, etiquetas)

        self._entrenado = True
        print("\n  🚀 Motor IA listo.\n")
        return self.metricas

    def analizar(self, paquete: Paquete) -> dict:
        """
        Analiza un paquete con los modelos disponibles y combina resultados.
        Retorna el veredicto final con etiqueta, score y modelo que ganó.
        """
        if not self._entrenado:
            raise RuntimeError("Motor IA no entrenado. Llama a entrenar() primero.")

        res_rf = self.rf.predecir(paquete)

        if self._usar_tf and self.autoencoder:
            res_ae = self.autoencoder.predecir(paquete)
        else:
            res_ae = {"es_amenaza": False, "confianza": 0.0, "etiqueta": "normal"}

        if self._usar_tf and self.cnn:
            res_cnn = self.cnn.predecir(paquete)
        else:
            res_cnn = {"es_amenaza": res_rf["es_amenaza"],
                       "confianza":  res_rf["confianza"],
                       "etiqueta":   res_rf["etiqueta"]}

        votos_amenaza = sum([
            res_rf["es_amenaza"]  * 0.40,
            res_cnn["es_amenaza"] * 0.40,
            res_ae["es_amenaza"]  * 0.20,
        ])
        es_amenaza = votos_amenaza >= 0.35

        if res_rf["confianza"] >= res_cnn["confianza"]:
            etiqueta_final = res_rf["etiqueta"]
            conf_final     = res_rf["confianza"]
            modelo_ganador = "Random Forest"
        else:
            etiqueta_final = res_cnn["etiqueta"]
            conf_final     = res_cnn["confianza"]
            modelo_ganador = "CNN"

        if res_ae.get("es_amenaza") and not es_amenaza:
            etiqueta_final = "anomalia"
            es_amenaza     = True
            conf_final     = res_ae["confianza"]
            modelo_ganador = "Autoencoder"

        paquete.etiqueta     = etiqueta_final
        paquete.score_riesgo = conf_final

        return {
            "etiqueta":       etiqueta_final,
            "confianza":      round(conf_final, 4),
            "es_amenaza":     es_amenaza,
            "modelo_ganador": modelo_ganador,
            "votos_amenaza":  round(votos_amenaza, 3),
            "detalle": {
                "random_forest": res_rf,
                "autoencoder":   res_ae,
                "cnn":           res_cnn,
            },
        }

    def esta_listo(self) -> bool:
        return self._entrenado

    def __str__(self) -> str:
        estado = "listo" if self._entrenado else "sin entrenar"
        modelos = "RF" + (" + Autoencoder + CNN" if self._usar_tf else " (solo)")
        return f"MotorIA [{estado}] — {modelos}"
