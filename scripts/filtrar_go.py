#!/usr/bin/env python3
"""Filtra os casos em Go do PatchEval-Verified e separa um piloto.

Uso:
    python3 scripts/filtrar_go.py dataset/patcheval_verified.json

Saídas (na pasta dados/ do projeto):
    go_cases.json   -> todos os casos em Go, no mesmo formato do dataset
    go_cases.csv    -> resumo (CVE, CWEs, repo, tamanho da função vulnerável)
    piloto.json     -> casos escolhidos para testar o pipeline
"""
import csv
import json
import sys
from collections import Counter
from pathlib import Path

DADOS = Path(__file__).resolve().parent.parent / "dados"

# Casos pequenos (1 função, 1 arquivo), de repositórios e famílias de CWE diferentes
PILOTO = [
    "CVE-2022-1992",   # gogs/gogs              - path traversal (CWE-22/73)
    "CVE-2022-4643",   # sajari/docconv         - injeção de comando (CWE-78/77/94)
    "CVE-2023-30625",  # rudderlabs/rudder-server - SQL injection (CWE-89)
    "CVE-2020-4037",   # oauth2-proxy           - open redirect (CWE-601)
    "CVE-2022-24450",  # nats-io/nats-server    - autorização ausente (CWE-862)
]


def linhas_vulneraveis(caso):
    return sum(int(f["end_line"]) - int(f["start_line"]) + 1 for f in caso["vul_func"])


def main(caminho):
    with open(caminho, encoding="utf-8") as f:
        dados = json.load(f)

    go = [c for c in dados if c["programming_language"] == "Go"]
    go.sort(key=linhas_vulneraveis)

    DADOS.mkdir(exist_ok=True)
    with open(DADOS / "go_cases.json", "w", encoding="utf-8") as f:
        json.dump(go, f, ensure_ascii=False, indent=2)

    with open(DADOS / "go_cases.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cve_id", "cwes", "repo", "n_funcoes", "n_arquivos",
                    "linhas_vulneraveis", "image_url"])
        for c in go:
            w.writerow([
                c["cve_id"],
                ";".join(c["cwe_info"]),
                c["repo"].split("github.com/")[-1],
                len(c["vul_func"]),
                len({fn["file_path"] for fn in c["vul_func"]}),
                linhas_vulneraveis(c),
                c["image_url"],
            ])

    por_id = {c["cve_id"]: c for c in go}
    piloto = [por_id[cve] for cve in PILOTO if cve in por_id]
    with open(DADOS / "piloto.json", "w", encoding="utf-8") as f:
        json.dump(piloto, f, ensure_ascii=False, indent=2)

    print(f"Total no dataset: {len(dados)}")
    print(f"Casos em Go: {len(go)}")
    print("CWEs mais frequentes (um caso pode ter mais de uma):")
    for cwe, n in Counter(k for c in go for k in c["cwe_info"]).most_common(10):
        print(f"  {cwe}: {n}")
    print(f"Piloto: {len(piloto)} casos -> {DADOS / 'piloto.json'}")
    print("Imagens Docker do piloto:")
    for c in piloto:
        print(f"  docker pull {c['image_url']}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
