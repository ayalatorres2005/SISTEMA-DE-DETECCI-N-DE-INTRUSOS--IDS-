"""
modelos/random_forest.py
Clasificador Random Forest para identificar tipos de ataque.
POO: Hereda DetectorBase, implementa métodos abstractos.
"""
import numpy as np
from modelos.detector_base import DetectorBase
from core.paquete import Paquete


class DetectorRandomForest(DetectorBase):
    """
    Clasifica paquetes en: normal, dos, portscan, bruteforce, mitm.
    Usa RandomForestClassifier de scikit-learn.
    """

    def __init__(self, n_arboles: int = 150, max_profundidad: int = None):
        super().__init__("Random Forest")
        self.n_arboles       = n_arboles
        self.max_profundidad = max_profundidad
        self._modelo         = None
        self._encoder        = None

    def entrenar(self, paquetes: list, etiquetas: list) -> dict:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import LabelEncoder
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score

        X = np.array([p.to_features() for p in paquetes])
        self._encoder = LabelEncoder()
        y = self._encoder.fit_transform(etiquetas)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        self._modelo = RandomForestClassifier(
            n_estimators=self.n_arboles,
            max_depth=self.max_profundidad,
            random_state=42,
            class_weight="balanced",
        )
        self._modelo.fit(X_train, y_train)

        y_pred = self._modelo.predict(X_test)
        acc    = accuracy_score(y_test, y_pred)

        self.entrenado = True
        self.metricas  = {"accuracy": round(acc, 4)}
        print(f"  ✅ Random Forest entrenado | accuracy={acc:.2%} | "
              f"muestras={len(paquetes)}")
        return self.metricas

    def predecir(self, paquete: Paquete) -> dict:
        if not self.entrenado:
            raise RuntimeError("Modelo no entrenado.")
        x    = np.array([paquete.to_features()])
        pred = self._modelo.predict(x)[0]
        prob = float(self._modelo.predict_proba(x)[0].max())
        etiq = str(self._encoder.inverse_transform([pred])[0])
        return {
            "etiqueta":   etiq,
            "confianza":  round(prob, 4),
            "es_amenaza": etiq != "normal",
            "modelo":     self.nombre,
        }

    def importancia_features(self) -> dict:
        """Retorna importancia de cada característica."""
        if not self.entrenado:
            return {}
        nombres = ["protocolo","tamanio","puerto_src","puerto_dst",
                   "hash_ip_src","hash_ip_dst"]
        return dict(zip(nombres, self._modelo.feature_importances_.tolist()))

