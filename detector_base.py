"""
modelos/autoencoder.py
Autoencoder para detección de anomalías (Anomaly Detection).
Aprende el patrón del tráfico NORMAL y detecta desviaciones.
POO: Hereda DetectorBase — mismo contrato, lógica no supervisada.
"""
import numpy as np
from modelos.detector_base import DetectorBase
from core.paquete import Paquete


class AutoencoderDetector(DetectorBase):
    """
    Red neuronal Autoencoder entrenada solo con tráfico normal.
    Un error de reconstrucción alto indica tráfico anómalo.

    Arquitectura: 6 → 16 → 8 → 4 → 8 → 16 → 6
    """

    def __init__(self, umbral_anomalia: float = 0.5):
        super().__init__("Autoencoder")
        self.umbral       = umbral_anomalia
        self._modelo      = None
        self._scaler      = None
        self._umbral_calc = umbral_anomalia   # se recalcula tras entrenar

    def _construir_modelo(self, n_features: int):
        import tensorflow as tf
        from tensorflow.keras import layers, Model

        tf.random.set_seed(42)

        entrada = layers.Input(shape=(n_features,), name="entrada")

        x = layers.Dense(16, activation="relu", name="enc_1")(entrada)
        x = layers.Dropout(0.1)(x)
        x = layers.Dense(8,  activation="relu", name="enc_2")(x)
        codigo = layers.Dense(4,  activation="relu", name="codigo")(x)

        x = layers.Dense(8,  activation="relu", name="dec_1")(codigo)
        x = layers.Dense(16, activation="relu", name="dec_2")(x)
        salida = layers.Dense(n_features, activation="linear", name="salida")(x)

        modelo = Model(inputs=entrada, outputs=salida, name="Autoencoder_IDS")
        modelo.compile(optimizer="adam", loss="mse")
        return modelo

    def entrenar(self, paquetes: list, etiquetas: list) -> dict:
        from sklearn.preprocessing import MinMaxScaler

        normales = [p for p, e in zip(paquetes, etiquetas) if e == "normal"]
        if len(normales) < 10:
            normales = paquetes

        X = np.array([p.to_features() for p in normales], dtype=np.float32)

        self._scaler = MinMaxScaler()
        X_norm = self._scaler.fit_transform(X)

        self._modelo = self._construir_modelo(X_norm.shape[1])

        history = self._modelo.fit(
            X_norm, X_norm,
            epochs=30,
            batch_size=16,
            validation_split=0.15,
            verbose=0,
            shuffle=True,
        )

        X_pred  = self._modelo.predict(X_norm, verbose=0)
        errores = np.mean(np.abs(X_norm - X_pred), axis=1)
        self._umbral_calc = float(np.mean(errores) + 2 * np.std(errores))

        self.entrenado = True
        loss_final     = history.history["loss"][-1]
        self.metricas  = {
            "loss_final":        round(loss_final, 6),
            "umbral_anomalia":   round(self._umbral_calc, 6),
            "muestras_normales": len(normales),
        }
        print(f"  ✅ Autoencoder entrenado | loss={loss_final:.6f} | "
              f"umbral={self._umbral_calc:.4f}")
        return self.metricas

    def predecir(self, paquete: Paquete) -> dict:
        if not self.entrenado:
            raise RuntimeError("Autoencoder no entrenado.")

        x     = np.array([paquete.to_features()], dtype=np.float32)
        x_sc  = self._scaler.transform(x)
        x_rec = self._modelo.predict(x_sc, verbose=0)
        error = float(np.mean(np.abs(x_sc - x_rec)))

        es_anomalia = error > self._umbral_calc
        confianza   = min(1.0, error / (self._umbral_calc * 2))

        paquete.anomalia_score = round(error, 4)

        return {
            "etiqueta":   "anomalia" if es_anomalia else "normal",
            "confianza":  round(confianza, 4),
            "es_amenaza": es_anomalia,
            "modelo":     self.nombre,
            "error_rec":  round(error, 6),
            "umbral":     round(self._umbral_calc, 6),
        }
