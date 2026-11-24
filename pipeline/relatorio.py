"""Escrita do resumo de uma execução do pipeline."""
import csv

# Colunas do resumo.csv, uma linha por caso avaliado.
COLUNAS = ["cve", "status", "aviso", "poc_bloqueada", "testes_quebrados", "corridas_novas",
           "gosec_novos", "semgrep_novos", "segundos"]


def escrever_resumo(caminho, resultados):
    """Grava em `caminho` um CSV com uma linha por resultado.

    As listas (testes quebrados, achados novos) viram contagens; o detalhe
    completo fica no resultado.json de cada caso. Campos ausentes (casos que
    pararam antes, como nao_aplicavel) ficam vazios ou zerados.
    """
    with open(caminho, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(COLUNAS)
        for r in resultados:
            w.writerow([r["cve"], r["status"], r.get("aviso", ""), r.get("poc_bloqueada", ""),
                        len(r.get("testes_quebrados", [])),
                        # corridas que surgiram com o patch (nunca negativo)
                        max(0, r.get("corridas_patch", 0) - r.get("corridas_base", 0)),
                        len(r.get("gosec_novos", [])), len(r.get("semgrep_novos", [])),
                        r["segundos"]])
