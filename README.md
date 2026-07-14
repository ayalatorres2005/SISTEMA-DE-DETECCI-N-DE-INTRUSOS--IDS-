# 🛡️ IDS FIEE — Sistema de Detección de Intrusos

Sistema de Detección de Intrusos (IDS) basado en **Programación Orientada a Objetos** e **Inteligencia Artificial**, desarrollado como proyecto del curso de POO.

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Estado](https://img.shields.io/badge/estado-en%20desarrollo-yellow)
![Licencia](https://img.shields.io/badge/licencia-académica-lightgrey)

</div>

---

## 📖 Descripción

Este proyecto simula un **IDS (Intrusion Detection System)** orientado a redes de telecomunicaciones. Combina un motor de reglas clásico con modelos de **Machine Learning** (Random Forest y, opcionalmente, TensorFlow) para clasificar tráfico de red simulado, generar alertas de seguridad y producir un reporte final en PDF.

---

## ⚙️ Flujo de ejecución (`main.py`)

El programa se ejecuta en **5 etapas** secuenciales:

| Etapa | Descripción |
|:---:|---|
| 1️⃣ | Inicialización de componentes (`Sniffer`, `MotorIA`, `GestorAlertas`, `Logger`, `GeneradorPDF`) |
| 2️⃣ | Generación del dataset de entrenamiento simulado (400 paquetes etiquetados) |
| 3️⃣ | Entrenamiento de los modelos de IA |
| 4️⃣ | Monitoreo de tráfico en vivo (60 paquetes) y detección de amenazas |
| 5️⃣ | Generación del reporte final en PDF |

```
Inicializar → Generar dataset → Entrenar IA → Monitorear tráfico → Generar PDF
```

---

## 🧩 Componentes principales

### 🔹 `core.sniffer.SnifferSimulado`
Simula la captura de paquetes de red, aplicando una lista negra de IPs y una semilla de aleatoriedad para reproducibilidad.

### 🔹 `modelos.motor_ia.MotorIA`
Motor de inteligencia artificial encargado de entrenar y analizar el tráfico. Detecta automáticamente si **TensorFlow** está disponible; si no, opera únicamente con **Random Forest** (modo *failsafe*).

### 🔹 `alertas.gestor_alertas.GestorAlertas`
Genera y clasifica las alertas de seguridad según su nivel de severidad:

- 🔴 **Críticas**
- 🟠 **Altas**
- 🟡 **Medias**
- 🟢 **Bajas**

### 🔹 `registro.logger.LoggerIDS`
Registra cada alerta detectada durante el monitoreo.

### 🔹 `registro.generador_pdf.GeneradorPDF`
Genera el reporte final en PDF con las métricas del modelo y las alertas detectadas.

---

## 📊 Resumen final

Al terminar la ejecución, el sistema imprime un resumen con:

- Total de paquetes analizados
- Total de amenazas detectadas
- Desglose por severidad (crítica, alta, media, baja)
- Ruta del reporte PDF generado

---

## 🖥️ Dashboard web (opcional)

El sistema incluye un dashboard web opcional para visualizar los resultados en tiempo real.

```bash
python main.py --dashboard
```

Esto levanta el servidor en `http://localhost:5000`.

---

## 🚀 Uso

```bash
# Ejecución estándar
python main.py

# Ejecución con dashboard web
python main.py --dashboard
```

> 💡 Si TensorFlow no está instalado, el sistema continúa funcionando normalmente usando solo Random Forest.

---

## 📁 Estructura relevante del proyecto

```
├── main.py
├── core/
│   └── sniffer.py
├── modelos/
│   └── motor_ia.py
├── alertas/
│   └── gestor_alertas.py
├── registro/
│   ├── logger.py
│   └── generador_pdf.py
└── dashboard/
    └── app.py
```

