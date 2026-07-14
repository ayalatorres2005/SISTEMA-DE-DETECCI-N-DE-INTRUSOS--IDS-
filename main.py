"""
modelos/cnn_clasificador.py
Red Neuronal Convolucional (CNN) para clasificar tráfico de red.
Trata el vector de características como una "señal 1D".
POO: Hereda DetectorBase — polimorfismo con predecir().
"""
import numpy as np
from modelos.detector_base import DetectorBase
from core.paquete import Paquete


class CNNClasificador(DetectorBase):
    """
    CNN 1D que clasifica paquetes en tipos de ataque.
    Arquitectura: Conv1D → MaxPool → Conv1D → Dense → Softmax
    """

    def __init__(self, epochs: int = 40):
        super().__init__("CNN 1D")
        self.epochs   = epochs
        self._modelo  = None
        self._encoder = None
        self._scaler  = None

    def _construir_modelo(self, n_features: int, n_clases: int):
        import tensorflow as tf
        from tensorflow.keras import layers, Model

        tf.random.set_seed(42)

        entrada = layers.Input(shape=(n_features, 1), name="entrada")

        x = layers.Conv1D(32, kernel_size=2, activation="relu", padding="same")(entrada)
        x = layers.MaxPooling1D(pool_size=2, padding="same")(x)
        x = layers.Conv1D(64, kernel_size=2, activation="relu", padding="same")(x)
        x = layers.GlobalAveragePooling1D()(x)
        x = layers.Dense(64, activation="relu")(x)
        x = layers.Dropout(0.3)(x)
        salida = layers.Dense(n_clases, activation="softmax", name="salida")(x)

        modelo = Model(inputs=entrada, outputs=salida, name="CNN_IDS")
        modelo.compile(
            optimizer="adam",
            loss="sparse_categorical_crossentropy",
            metrics=["accuracy"],
        )
        return modelo

    def entrenar(self, paquetes: list, etiquetas: list) -> dict:
        import tensorflow as tf
        from sklearn.preprocessing import LabelEncoder, MinMaxScaler
        from sklearn.model_selection import train_test_split

        X_raw = np.array([p.to_features() for p in paquetes], dtype=np.float32)
        self._scaler  = MinMaxScaler()
        X = self._scaler.fit_transform(X_raw)
        X = X.reshape(X.shape[0], X.shape[1], 1)

        self._encoder = LabelEncoder()
        y = self._encoder.fit_transform(etiquetas)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        n_clases     = len(np.unique(y))
        self._modelo = self._construir_modelo(X.shape[1], n_clases)

        early_stop = tf.keras.callbacks.EarlyStopping(
            patience=8, restore_best_weights=True, monitor="val_accuracy"
        )

        history = self._modelo.fit(
            X_train, y_train,
            epochs=self.epochs,
            batch_size=32,
            validation_data=(X_test, y_test),
            callbacks=[early_stop],
            verbose=0,
        )

        _, acc = self._modelo.evaluate(X_test, y_test, verbose=0)
        self.entrenado = True
        self.metricas  = {
            "accuracy":      round(float(acc), 4),
            "epochs_reales": len(history.history["loss"]),
            "n_clases":      n_clases,
        }
        print(f"  ✅ CNN entrenada | accuracy={acc:.2%} | "
              f"epochs={self.metricas['epochs_reales']}")
        return self.metricas

    def predecir(self, paquete: Paquete) -> dict:
        if not self.entrenado:
            raise RuntimeError("CNN no entrenada.")

        x    = np.array([paquete.to_features()], dtype=np.float32)
        x_sc = self._scaler.transform(x)
        x_rs = x_sc.reshape(1, x_sc.shape[1], 1)

        probs = self._modelo.predict(x_rs, verbose=0)[0]
        idx   = int(np.argmax(probs))
        etiq  = str(self._encoder.inverse_transform([idx])[0])
        conf  = float(probs[idx])

        return {
            "etiqueta":   etiq,
            "confianza":  round(conf, 4),
            "es_amenaza": etiq != "normal",
            "modelo":     self.nombre,
            "probs":      {cls: round(float(p), 4)
                           for cls, p in zip(self._encoder.classes_, probs)},
        }
