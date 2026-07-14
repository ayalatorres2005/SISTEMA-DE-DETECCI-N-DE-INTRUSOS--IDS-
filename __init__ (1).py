# IDS FIEE — Sistema de Detección de Intrusos

**Curso**: Programación Orientada a Objetos
**Tema**: Gestión de Ciberseguridad en Redes de Telecomunicaciones

## Estructura del proyecto

```
ids_fiee/
├── main.py                         # Punto de entrada principal
├── requirements.txt
├── README.md
│
├── core/                           # Captura de tráfico
│   ├── paquete.py                  # Entidad Paquete
│   └── sniffer.py                  # CapturadorBase + Sniffer + SnifferSimulado
│
├── modelos/                        # Inteligencia Artificial
│   ├── detector_base.py            # Clase abstracta DetectorBase
│   ├── random_forest.py            # Clasificador Random Forest
│   ├── autoencoder.py              # Autoencoder (anomaly detection)
│   ├── cnn_clasificador.py         # CNN 1D
│   └── motor_ia.py                 # Orquestador (RF + AE + CNN)
│
├── alertas/
│   └── gestor_alertas.py           # NivelRiesgo + Alerta + GestorAlertas
│
├── registro/
│   ├── logger.py                   # LoggerIDS — SQLite + JSON
│   └── generador_pdf.py            # Reportes PDF
│
├── dashboard/
│   └── app.py                      # Servidor Flask
│
└── templates/
    └── dashboard.html              # Interfaz del dashboard
```

Nota: las carpetas `logs/` y `reportes/` se crean automáticamente la
primera vez que corres el programa (no vienen incluidas en el ZIP).

## Instalación

```bash
pip install scikit-learn numpy reportlab flask
pip install tensorflow      # opcional, para Autoencoder y CNN
```

## Ejecución

```bash
python main.py                # análisis completo + PDF
python main.py --dashboard    # + dashboard en http://localhost:5000
```

Si TensorFlow no está instalado, el sistema usa automáticamente
solo Random Forest, sin fallar.

## Principios POO implementados

| Principio       | Dónde                                           |
|-----------------|--------------------------------------------------|
| Abstracción     | `CapturadorBase`, `DetectorBase` (ABC)           |
| Herencia        | `Sniffer`, `SnifferSimulado` → `CapturadorBase`  |
| Polimorfismo    | `RF`, `CNN`, `Autoencoder` comparten `predecir()`|
| Encapsulamiento | Atributos privados `_modelo`, `_historial`       |
| Composición     | `MotorIA` contiene RF + Autoencoder + CNN        |
| SRP             | `LoggerIDS` solo persiste, `GeneradorPDF` solo genera reportes |
