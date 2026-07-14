"""
registro/logger.py
Registro persistente de alertas en SQLite.
POO: Responsabilidad Única (SRP) — solo persiste y consulta.
"""
import json
import sqlite3
from pathlib import Path
from alertas.gestor_alertas import Alerta


class LoggerIDS:
    """
    Almacena alertas en base de datos SQLite y en archivo JSON.
    Permite consultas históricas para el dashboard y reportes.
    """

    def __init__(self, ruta_db: str = "logs/ids_fiee.db",
                 ruta_json: str = "logs/alertas.json"):
        self._ruta_db   = Path(ruta_db)
        self._ruta_json = Path(ruta_json)
        self._ruta_db.parent.mkdir(parents=True, exist_ok=True)
        self._inicializar_db()
        self._cache: list = []

    def _inicializar_db(self):
        with sqlite3.connect(self._ruta_db) as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS alertas (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp    TEXT,
                    nivel        TEXT,
                    tipo_ataque  TEXT,
                    score        INTEGER,
                    confianza    REAL,
                    ip_origen    TEXT,
                    ip_destino   TEXT,
                    protocolo    TEXT,
                    puerto_dst   INTEGER,
                    accion       TEXT,
                    modelo       TEXT,
                    atendida     INTEGER DEFAULT 0
                )
            """)
            con.commit()

    def registrar(self, alerta: Alerta) -> None:
        datos = alerta.to_dict()
        with sqlite3.connect(self._ruta_db) as con:
            con.execute("""
                INSERT INTO alertas
                (timestamp, nivel, tipo_ataque, score, confianza,
                 ip_origen, ip_destino, protocolo, puerto_dst, accion, modelo)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (
                datos["timestamp"], datos["nivel"], datos["tipo_ataque"],
                datos["score"],     datos["confianza"], datos["ip_origen"],
                datos["ip_destino"], datos["protocolo"], datos["puerto_dst"],
                datos["accion"],    datos["modelo_origen"],
            ))
            con.commit()
        self._cache.append(datos)
        self._persistir_json(datos)

    def _persistir_json(self, entrada: dict):
        with open(self._ruta_json, "a", encoding="utf-8") as f:
            f.write(json.dumps(entrada, ensure_ascii=False) + "\n")

    def obtener_todas(self) -> list:
        with sqlite3.connect(self._ruta_db) as con:
            con.row_factory = sqlite3.Row
            rows = con.execute(
                "SELECT * FROM alertas ORDER BY timestamp DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def obtener_recientes(self, n: int = 20) -> list:
        with sqlite3.connect(self._ruta_db) as con:
            con.row_factory = sqlite3.Row
            rows = con.execute(
                "SELECT * FROM alertas ORDER BY timestamp DESC LIMIT ?", (n,)
            ).fetchall()
        return [dict(r) for r in rows]

    def estadisticas(self) -> dict:
        with sqlite3.connect(self._ruta_db) as con:
            total    = con.execute("SELECT COUNT(*) FROM alertas").fetchone()[0]
            criticas = con.execute(
                "SELECT COUNT(*) FROM alertas WHERE nivel='CRÍTICO'"
            ).fetchone()[0]
            por_tipo = con.execute(
                "SELECT tipo_ataque, COUNT(*) FROM alertas GROUP BY tipo_ataque"
            ).fetchall()
        return {
            "total":    total,
            "criticas": criticas,
            "por_tipo": dict(por_tipo),
        }

    def total(self) -> int:
        with sqlite3.connect(self._ruta_db) as con:
            return con.execute("SELECT COUNT(*) FROM alertas").fetchone()[0]
