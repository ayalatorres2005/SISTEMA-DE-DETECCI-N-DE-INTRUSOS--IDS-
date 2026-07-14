"""
dashboard/app.py
Dashboard web con Flask para visualizar alertas en tiempo real.
POO: Composición — usa LoggerIDS como dependencia.
"""
from flask import Flask, render_template, jsonify
from registro.logger import LoggerIDS

app = Flask(
    __name__,
    template_folder="../templates",
)

_logger: LoggerIDS = None

def inicializar(logger: LoggerIDS):
    global _logger
    _logger = logger


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/alertas")
def api_alertas():
    if not _logger:
        return jsonify({"error": "Logger no inicializado"}), 500
    return jsonify(_logger.obtener_recientes(50))


@app.route("/api/estadisticas")
def api_estadisticas():
    if not _logger:
        return jsonify({"error": "Logger no inicializado"}), 500
    return jsonify(_logger.estadisticas())


@app.route("/api/alertas/recientes/<int:n>")
def api_alertas_recientes(n: int):
    if not _logger:
        return jsonify([]), 500
    return jsonify(_logger.obtener_recientes(n))


def run(logger: LoggerIDS, host: str = "0.0.0.0", port: int = 5000):
    inicializar(logger)
    print(f"\n  🌐 Dashboard disponible en http://localhost:{port}\n")
    app.run(host=host, port=port, debug=False)
