"""
registro/generador_pdf.py
Genera reportes PDF automáticos del análisis IDS.
POO: Responsabilidad Única — solo genera reportes visuales.
"""
from pathlib import Path
from datetime import datetime


class GeneradorPDF:
    """
    Genera reportes PDF profesionales con ReportLab.
    Incluye: resumen ejecutivo, tabla de alertas, métricas de IA.
    """

    def __init__(self, ruta_salida: str = "reportes"):
        self.ruta = Path(ruta_salida)
        self.ruta.mkdir(parents=True, exist_ok=True)

    def generar(self, alertas: list, metricas_ia: dict,
                paquetes_analizados: int) -> str:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, HRFlowable)
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units  import cm
        from reportlab.lib.enums  import TA_CENTER

        nombre   = f"reporte_ids_{datetime.now():%Y%m%d_%H%M%S}.pdf"
        ruta_pdf = self.ruta / nombre

        doc = SimpleDocTemplate(
            str(ruta_pdf), pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2*cm,  bottomMargin=2*cm,
        )

        styles = getSampleStyleSheet()
        azul   = colors.Color(0.05, 0.27, 0.55)

        estilo_titulo = ParagraphStyle(
            "titulo", parent=styles["Title"],
            fontSize=20, textColor=azul,
            spaceAfter=4, alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        )
        estilo_subtitulo = ParagraphStyle(
            "subtitulo", parent=styles["Normal"],
            fontSize=11, textColor=colors.gray,
            spaceAfter=12, alignment=TA_CENTER,
        )
        estilo_seccion = ParagraphStyle(
            "seccion", parent=styles["Heading2"],
            fontSize=13, textColor=azul,
            spaceBefore=16, spaceAfter=6,
            fontName="Helvetica-Bold",
        )
        estilo_normal = ParagraphStyle(
            "normal_ids", parent=styles["Normal"],
            fontSize=9, leading=14,
        )

        story = []

        story.append(Spacer(1, 1*cm))
        story.append(Paragraph("SISTEMA DE DETECCIÓN DE INTRUSOS", estilo_titulo))
        story.append(Paragraph("IDS FIEE — Reporte de Análisis de Seguridad", estilo_subtitulo))
        story.append(Paragraph(
            f"Generado: {datetime.now():%d/%m/%Y %H:%M:%S}  |  "
            f"Paquetes analizados: {paquetes_analizados}  |  "
            f"Alertas generadas: {len(alertas)}",
            ParagraphStyle("meta", parent=styles["Normal"],
                           fontSize=8, textColor=colors.gray, alignment=TA_CENTER)
        ))
        story.append(HRFlowable(width="100%", thickness=2, color=azul, spaceAfter=12))

        story.append(Paragraph("1. Resumen Ejecutivo", estilo_seccion))

        criticas = sum(1 for a in alertas if a.get("nivel") == "CRÍTICO")
        altas    = sum(1 for a in alertas if a.get("nivel") == "ALTO")
        medias   = sum(1 for a in alertas if a.get("nivel") == "MEDIO")
        bajas    = sum(1 for a in alertas if a.get("nivel") == "BAJO")

        resumen_data = [
            ["Métrica", "Valor", "Estado"],
            ["Paquetes analizados", str(paquetes_analizados), "✓"],
            ["Total alertas",       str(len(alertas)),        "✓"],
            ["Alertas CRÍTICAS",    str(criticas), "⚠" if criticas > 0 else "✓"],
            ["Alertas ALTAS",       str(altas),    "⚠" if altas    > 0 else "✓"],
            ["Alertas MEDIAS",      str(medias),   "—"],
            ["Alertas BAJAS",       str(bajas),    "—"],
        ]

        t = Table(resumen_data, colWidths=[8*cm, 4*cm, 4*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,0),  azul),
            ("TEXTCOLOR",   (0,0), (-1,0),  colors.white),
            ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 9),
            ("ALIGN",       (1,0), (-1,-1), "CENTER"),
            ("ROWBACKGROUNDS", (0,1), (-1,-1),
             [colors.Color(0.95,0.97,1.0), colors.white]),
            ("GRID",        (0,0), (-1,-1), 0.5, colors.lightgrey),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.5*cm))

        story.append(Paragraph("2. Desempeño de Modelos de IA", estilo_seccion))

        ia_data = [["Modelo", "Métrica Principal", "Valor"]]
        if "random_forest" in metricas_ia:
            m = metricas_ia["random_forest"]
            ia_data.append(["Random Forest", "Accuracy",
                             f"{m.get('accuracy', 0):.2%}"])
        if "autoencoder" in metricas_ia:
            m = metricas_ia["autoencoder"]
            ia_data.append(["Autoencoder", "Umbral anomalía",
                             f"{m.get('umbral_anomalia', 0):.4f}"])
        if "cnn" in metricas_ia:
            m = metricas_ia["cnn"]
            ia_data.append(["CNN 1D", "Accuracy",
                             f"{m.get('accuracy', 0):.2%}"])

        t2 = Table(ia_data, colWidths=[6*cm, 6*cm, 4*cm])
        t2.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,0),  colors.Color(0.3,0.4,0.7)),
            ("TEXTCOLOR",   (0,0), (-1,0),  colors.white),
            ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 9),
            ("ALIGN",       (2,0), (2,-1),  "CENTER"),
            ("ROWBACKGROUNDS", (0,1), (-1,-1),
             [colors.Color(0.95,0.97,1.0), colors.white]),
            ("GRID",        (0,0), (-1,-1), 0.5, colors.lightgrey),
        ]))
        story.append(t2)
        story.append(Spacer(1, 0.5*cm))

        story.append(Paragraph("3. Registro de Alertas Detectadas", estilo_seccion))

        if alertas:
            cols = ["Hora", "Nivel", "Tipo Ataque", "IP Origen",
                    "Puerto", "Score", "Acción"]
            tabla_data = [cols]
            for a in alertas[:40]:
                hora = a.get("timestamp", "")[:19].replace("T", " ")[-8:]
                tabla_data.append([
                    hora,
                    a.get("nivel", ""),
                    a.get("tipo_ataque", "").upper(),
                    a.get("ip_origen", ""),
                    str(a.get("puerto_dst", "")),
                    str(a.get("score", "")),
                    a.get("accion", "")[:35],
                ])

            ta = Table(tabla_data,
                       colWidths=[1.8*cm, 2*cm, 2.4*cm, 3.2*cm,
                                  1.5*cm, 1.5*cm, 4.6*cm])
            ta.setStyle(TableStyle([
                ("BACKGROUND",  (0,0), (-1,0),  azul),
                ("TEXTCOLOR",   (0,0), (-1,0),  colors.white),
                ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
                ("FONTSIZE",    (0,0), (-1,-1), 7),
                ("ROWBACKGROUNDS", (0,1), (-1,-1),
                 [colors.Color(0.95,0.97,1.0), colors.white]),
                ("GRID",        (0,0), (-1,-1), 0.3, colors.lightgrey),
                ("ALIGN",       (4,0), (5,-1),  "CENTER"),
            ]))
            story.append(ta)
        else:
            story.append(Paragraph("No se detectaron alertas en este análisis.",
                                   estilo_normal))

        story.append(Spacer(1, 1*cm))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=colors.lightgrey, spaceAfter=6))
        story.append(Paragraph(
            "IDS FIEE — Sistema de Detección de Intrusos | "
            "Programación Orientada a Objetos | Python + IA",
            ParagraphStyle("pie", parent=styles["Normal"],
                           fontSize=7, textColor=colors.gray,
                           alignment=TA_CENTER)
        ))

        doc.build(story)
        print(f"  📄 PDF generado: {ruta_pdf}")
        return str(ruta_pdf)
