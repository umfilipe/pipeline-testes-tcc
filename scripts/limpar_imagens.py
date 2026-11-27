#!/usr/bin/env python3
"""Remove as imagens Docker do PatchEval para liberar espaço em disco.

Uso (a partir da raiz do projeto), depois de terminar todas as execuções do
pipeline que usam as imagens:
    python3 scripts/limpar_imagens.py dados/sorteio5.json           # imagens destes casos
    python3 scripts/limpar_imagens.py dados/sorteio5.json --simular # só mostra o que faria
    python3 scripts/limpar_imagens.py --todas                       # todas as do PatchEval

Só mexe em imagens ghcr.io/patcheval-cve/... e em containers parados criados
pelo pipeline (nome começando com tcc_) a partir delas; outras imagens e
containers do Docker ficam intactos. Uma imagem com container em execução
(por exemplo, o pipeline ainda rodando) não é removida.

Rodar o pipeline de novo depois da limpeza baixa as imagens outra vez.
"""
import argparse
import json
import subprocess
import sys

PREFIXO = "ghcr.io/patcheval-cve/"


def docker(*args):
    """Roda `docker` e devolve (código de saída, saída)."""
    p = subprocess.run(["docker", *args], capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


def imagens_locais():
    """{imagem: tamanho} das imagens do PatchEval baixadas."""
    cod, out = docker("images", "--format", "{{.Repository}}:{{.Tag}}\t{{.Size}}")
    if cod != 0:
        sys.exit(f"não consegui falar com o Docker: {out}")
    linhas = (l.split("\t") for l in out.splitlines() if l.startswith(PREFIXO))
    return dict(linhas)


def containers_da_imagem(imagem):
    """Lista (nome, estado) dos containers criados a partir de `imagem`."""
    _, out = docker("ps", "-a", "--filter", f"ancestor={imagem}",
                    "--format", "{{.Names}}\t{{.State}}")
    return [tuple(l.split("\t")) for l in out.splitlines() if l]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("casos", nargs="*", help="JSONs de casos (ex.: dados/sorteio5.json)")
    ap.add_argument("--todas", action="store_true", help="remover todas as imagens do PatchEval")
    ap.add_argument("--simular", action="store_true", help="só mostrar o que seria removido")
    args = ap.parse_args()
    if bool(args.casos) == args.todas:
        sys.exit("passe os arquivos de casos ou --todas (um dos dois)")

    locais = imagens_locais()
    if args.todas:
        alvos = sorted(locais)
    else:
        pedidas = {c["image_url"] for arq in args.casos
                   for c in json.load(open(arq, encoding="utf-8"))}
        alvos = sorted(i for i in pedidas if i in locais)
        if not all(i.startswith(PREFIXO) for i in pedidas):
            sys.exit(f"os casos têm imagens fora de {PREFIXO}; nada foi removido")
    if not alvos:
        print("nenhuma imagem do PatchEval para remover")
        return

    removidas, puladas = 0, 0
    for img in alvos:
        conts = containers_da_imagem(img)
        rodando = [n for n, estado in conts if estado == "running"]
        alheios = [n for n, _ in conts if not n.startswith("tcc_")]
        if rodando or alheios:
            # container em execução (pipeline rodando) ou que não é do pipeline: não mexe
            print(f"pulando {img}: containers {', '.join(rodando + alheios)}")
            puladas += 1
            continue
        if args.simular:
            print(f"removeria {img} ({locais[img]})")
            continue
        for nome, _ in conts:  # sobras paradas do pipeline (ex.: execução interrompida)
            docker("rm", nome)
        cod, out = docker("rmi", img)
        if cod == 0:
            print(f"removida {img} ({locais[img]})")
            removidas += 1
        else:
            print(f"falha ao remover {img}: {out}")
            puladas += 1

    if not args.simular:
        # camadas que ficaram sem nenhuma imagem; só as soltas (dangling), não mexe em outras
        docker("image", "prune", "-f")
        print(f"{removidas} imagens removidas, {puladas} puladas")


if __name__ == "__main__":
    main()
