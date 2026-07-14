"""
main.py — IDS FIEE
Sistema de Detección de Intrusos basado en POO + IA
Curso: Programación Orientada a Objetos

Autor   : [Tu nombre]
Curso   : Programación Orientada a Objetos
Fecha   : 2025
"""
import sys


def cabecera():
    print("\n" + "="*62)
    print("   SISTEMA DE DETECCIÓN DE INTRUSOS (IDS) — FIEE")
    print("   Ciberseguridad en Redes de Telecomunicaciones — POO")
    print("="*62 + "\n")


def main():
    cabecera()

    from core.sniffer           import SnifferSimulado
    from modelos.motor_ia       import MotorIA
    from alertas.gestor_alertas import GestorAlertas
    from registro.logger        import LoggerIDS
    from registro.generador_pdf import GeneradorPDF

    # Detectar si TensorFlow está disponible (failsafe)
    try:
        import tensorflow  # noqa: F401
        usar_tf = True
    except ImportError:
        print("  [INFO] TensorFlow no encontrado. Se usará solo Random Forest.\n")
        usar_tf = False

    # ── 1. INICIALIZAR COMPONENTES ───────────────────────────────────
    print("▶ [1/5] Inicializando componentes del sistema...")
    sniffer  = SnifferSimulado(lista_negra=["203.0.113.4"], semilla=99)
    motor    = MotorIA(usar_tensorflow=usar_tf)
    gestor   = GestorAlertas()
    logger   = LoggerIDS()
    pdf_gen  = GeneradorPDF()
    print("   ✓ Sniffer, MotorIA, GestorAlertas, Logger, PDF — listos\n")

    # ── 2. GENERAR DATOS DE ENTRENAMIENTO ────────────────────────────
    print("▶ [2/5] Generando dataset de entrenamiento (simulado)...")
    paquetes_train, etiquetas_train = sniffer.generar_con_etiquetas(cantidad=400)
    from collections import Counter
    dist = Counter(etiquetas_train)
    for etiq, cnt in dist.items():
        print(f"   {etiq:12s}: {cnt} muestras")
    print()

    # ── 3. ENTRENAR MODELOS DE IA ────────────────────────────────────
    print("▶ [3/5] Entrenando modelos de IA...")
    metricas_ia = motor.entrenar(paquetes_train, etiquetas_train)

    # ── 4. MONITOREAR TRÁFICO EN VIVO ───────────────────────────────
    print("▶ [4/5] Monitoreando tráfico de red (60 paquetes)...")
    paquetes_live = sniffer.capturar(cantidad=60)
    paquetes_live = sniffer.filtrar(paquetes_live)
    print(f"   Paquetes capturados y filtrados: {len(paquetes_live)}\n")

    amenazas = 0
    for pkt in paquetes_live:
        resultado = motor.analizar(pkt)
        alerta    = gestor.crear_alerta(pkt, resultado)
        if alerta:
            amenazas += 1
            print(f"   {alerta}")
            logger.registrar(alerta)

    print(f"\n   Total amenazas detectadas: {amenazas} / {len(paquetes_live)}")

    # ── 5. GENERAR REPORTE PDF ──────────────────────────────────────
    print("\n▶ [5/5] Generando reporte PDF...")
    alertas_dict = [a.to_dict() for a in gestor.todas()]
    ruta_pdf     = pdf_gen.generar(alertas_dict, metricas_ia, len(paquetes_live))

    # ── RESUMEN FINAL ────────────────────────────────────────────────
    resumen = gestor.resumen()
    print("\n" + "="*62)
    print("   RESUMEN FINAL DEL ANÁLISIS")
    print("="*62)
    print(f"   Paquetes analizados : {len(paquetes_live)}")
    print(f"   Amenazas detectadas : {resumen['total']}")
    print(f"   🔴 Críticas         : {resumen['criticas']}")
    print(f"   🟠 Altas            : {resumen['altas']}")
    print(f"   🟡 Medias           : {resumen['medias']}")
    print(f"   🟢 Bajas            : {resumen['bajas']}")
    print(f"   Reporte PDF         : {ruta_pdf}")
    print("="*62)

    # ── DASHBOARD WEB (opcional) ────────────────────────────────────
    if "--dashboard" in sys.argv:
        from dashboard.app import run as run_dashboard
        run_dashboard(logger, port=5000)


if __name__ == "__main__":
    main()
