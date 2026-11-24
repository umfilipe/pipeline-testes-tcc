"""Interface de linha de comando do pipeline.

Rode a partir da raiz do projeto:
  python3 -m pipeline --casos dados/piloto.json --oficial --saida resultados/oficial \\
      --semgrep-config config/regras_semgrep_golang.yaml
  python3 -m pipeline --casos dados/piloto.json --patches patches/patches_claude-opus.json \\
      --saida resultados/claude-opus --semgrep-config config/regras_semgrep_golang.yaml

Entrada (--patches): lista JSON em um destes formatos por item
  {"cve": "CVE-...", "fix_patch": "diff --git ..."}   # diff pronto
  {"cve": "CVE-...", "funcoes": ["func ...", ...]}      # funções corrigidas, na mesma ordem de vul_func

Com --oficial, o pipeline baixa do GitHub o diff do commit de correção (patch_url)
e mantém só os arquivos .go de código (sem testes, go.mod e go.sum). Use isso
primeiro: a PoC deve ser bloqueada em todos os casos. Se não for, o problema
está no pipeline, e não no modelo.

Requisitos no computador (fora do container):
  - docker
  - semgrep  (pipx install semgrep)
  - gosec compilado de forma estática:
      CGO_ENABLED=0 go install github.com/securego/gosec/v2/cmd/gosec@latest
"""
import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from .avaliacao import avaliar
from .config import SEMGREP_CONFIG
from .patches import baixar_patch_oficial, funcoes_oficiais
from .relatorio import escrever_resumo


def ler_argumentos():
    """Define e lê os argumentos da linha de comando."""
    ap = argparse.ArgumentParser(prog="python3 -m pipeline", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--casos", required=True, help="dados/piloto.json ou dados/go_cases.json")
    ap.add_argument("--patches", help="JSON com os patches do modelo")
    ap.add_argument("--oficial", action="store_true", help="usar a correção oficial (teste de sanidade)")
    ap.add_argument("--saida", required=True, help="pasta dos resultados (ex.: resultados/claude-opus)")
    ap.add_argument("--cve", nargs="+", help="avaliar só estes CVEs")
    ap.add_argument("--semgrep-config", default=SEMGREP_CONFIG,
                    help="arquivo local de regras (recomendado, para resultados reproduzíveis)")
    ap.add_argument("--gosec", default=shutil.which("gosec") or "gosec",
                    help="caminho do binário do gosec (padrão: o do PATH)")
    return ap.parse_args()


def checar_requisitos(args):
    """Encerra com uma mensagem clara se faltar algum argumento ou programa."""
    if not args.oficial and not args.patches:
        sys.exit("use --patches ARQUIVO ou --oficial")
    for prog in ("docker", "semgrep"):
        if not shutil.which(prog):
            sys.exit(f"{prog} não encontrado no PATH")
    if not os.path.isfile(args.gosec):
        sys.exit("gosec não encontrado; instale com CGO_ENABLED=0 go install "
                 "github.com/securego/gosec/v2/cmd/gosec@latest ou passe --gosec CAMINHO")


def carregar_patches(args, casos):
    """Monta o dicionário {CVE: item de patch} a avaliar.

    Com --oficial, cada item tem o diff do GitHub ("fix_patch", se o download
    funcionar) e as funções de fix_func ("funcoes") como alternativa.
    Sem --oficial, lê o arquivo passado em --patches.
    """
    if args.oficial:
        itens = {}
        for c in casos:
            diff, erro = baixar_patch_oficial(c)
            item = {"funcoes": funcoes_oficiais(c)}
            if erro:
                print(f"[{c['cve_id']}] diff oficial indisponível ({erro}); usando fix_func")
            else:
                item["fix_patch"] = diff
            itens[c["cve_id"]] = item
        return itens
    return {p["cve"]: p for p in json.load(open(args.patches, encoding="utf-8"))}


def mostrar_achados(log):
    """Destaca no terminal os achados novos de análise estática: o caminho do log
    e, para cada achado, a ferramenta, o arquivo, a linha e o código ao redor.
    Usa vermelho só quando a saída é um terminal (não suja arquivos de log)."""
    cor = sys.stdout.isatty()
    vermelho, fim = ("\033[1;31m", "\033[0m") if cor else ("", "")
    print(f"{vermelho}  ✗ achados novos de análise estática; log em {log}{fim}")
    for linha in log.read_text().splitlines():
        print(f"    {linha}")
    print(flush=True)


def main():
    args = ler_argumentos()
    checar_requisitos(args)

    # casos do benchmark, opcionalmente restritos aos CVEs de --cve
    casos = json.load(open(args.casos, encoding="utf-8"))
    if args.cve:
        casos = [c for c in casos if c["cve_id"] in args.cve]
    itens = carregar_patches(args, casos)

    saida = Path(args.saida)
    saida.mkdir(parents=True, exist_ok=True)
    resultados = []
    for caso in casos:
        cve = caso["cve_id"]
        if cve not in itens:
            print(f"[{cve}] sem patch, pulando")
            continue
        # cada caso tem sua própria pasta com o resultado.json e os artefatos
        pasta = saida / cve
        pasta.mkdir(exist_ok=True)
        print(f"[{cve}] avaliando...", flush=True)
        r = avaliar(caso, itens[cve], args, pasta)
        (pasta / "resultado.json").write_text(json.dumps(r, indent=2, ensure_ascii=False))
        print(f"[{cve}] {r['status']} ({r['segundos']}s)", flush=True)
        if (pasta / "achados_novos.log").exists():
            # aparece em qualquer status: o achado pode vir junto de outra falha
            mostrar_achados(pasta / "achados_novos.log")
        resultados.append(r)

    escrever_resumo(saida / "resumo.csv", resultados)
    print(f"Resumo em {saida / 'resumo.csv'}")


if __name__ == "__main__":
    main()
