#!/usr/bin/env python3
"""Converte as respostas dos modelos no JSON de patches que o pipeline (pasta pipeline/) lê.

Uso:
    python3 scripts/montar_patches.py dados/piloto.json respostas/claude-opus patches/patches_claude-opus.json

Na pasta de respostas, um arquivo por caso:
    <CVE>.md     resposta completa do modelo (o script extrai os blocos ```go)
    <CVE>.patch  ou um diff pronto (por exemplo, `git diff` de uma edição feita à mão)
"""
import json
import re
import sys
from pathlib import Path

BLOCO_GO = re.compile(r"```(?:go|golang)?[ \t]*\n(.*?)```", re.S)


INICIO_GO = re.compile(r"^(func|var|const|type)\b")


def extrair_sem_cercas(texto):
    """Resposta colada sem ```go (copiada já renderizada): pega do primeiro
    `func`/`var`/`const`/`type` no início da linha até o último `}` ou `)` que
    fecha um bloco na coluna 0."""
    linhas = texto.splitlines()
    ini = next((i for i, l in enumerate(linhas) if INICIO_GO.match(l.lstrip())), None)
    if ini is None:
        return None
    fim = None
    for i in range(ini, len(linhas)):
        if linhas[i].rstrip() in ("}", ")"):
            fim = i
    if fim is None:
        return None
    trecho = linhas[ini:fim + 1]
    # remove o recuo comum (o chat costuma colar com espaços na frente)
    recuo = min((len(l) - len(l.lstrip()) for l in trecho if l.strip()), default=0)
    return "\n".join(l[recuo:] if len(l) >= recuo else l for l in trecho)


def _normalizar(codigo):
    """Junta espaços em branco, para comparar código sem depender de indentação."""
    return re.sub(r"\s+", " ", codigo).strip()


def _e_declaracao(bloco):
    """True se o bloco é uma declaração Go completa: a primeira linha que não é
    comentário nem vazia começa com func, var, const ou type."""
    for linha in bloco.splitlines():
        l = linha.strip()
        if not l or l.startswith("//"):
            continue
        return bool(INICIO_GO.match(l))
    return False


def extrair_funcoes(texto, n_funcoes, vulneraveis=()):
    """Extrai da resposta as funções corrigidas; devolve (lista de funções, erro).

    Dois tipos de bloco ```go são descartados, porque viram código inválido no patch:
      - blocos idênticos ao código vulnerável (`vulneraveis`): alguns modelos
        citam o original antes de mostrar a correção;
      - blocos que não são declarações completas (func/var/const/type): trechos
        soltos citados na explicação, como uma linha ou uma expressão.
    """
    originais = {_normalizar(v) for v in vulneraveis}
    blocos = [b.strip("\n") for b in BLOCO_GO.findall(texto)
              if b.strip() and _normalizar(b) not in originais and _e_declaracao(b)]
    if not blocos:
        bloco = extrair_sem_cercas(texto)
        if bloco and n_funcoes == 1:
            return [bloco], None
        return None, "nenhum bloco de código encontrado na resposta"
    if n_funcoes == 1:
        # um único alvo: todos os blocos viram o substituto (função + auxiliares)
        return ["\n\n".join(blocos)], None
    if len(blocos) != n_funcoes:
        return None, f"esperava {n_funcoes} blocos, a resposta tem {len(blocos)}"
    return blocos, None


def main(casos_json, pasta, saida):
    pasta = Path(pasta)
    itens, problemas = [], []
    for caso in json.load(open(casos_json, encoding="utf-8")):
        cve = caso["cve_id"]
        diff, resp = pasta / f"{cve}.patch", pasta / f"{cve}.md"
        if diff.exists():
            itens.append({"cve": cve, "fix_patch": diff.read_text(encoding="utf-8")})
        elif resp.exists() and not resp.read_text(encoding="utf-8").strip():
            # arquivo criado pelo gerar_prompts.py, mas a resposta ainda não foi colada
            problemas.append(f"{cve}: {resp.name} está vazio (resposta ainda não colada)")
        elif resp.exists():
            funcoes, erro = extrair_funcoes(resp.read_text(encoding="utf-8"),
                                            len(caso["vul_func"]),
                                            [f["snippet"] for f in caso["vul_func"]])
            if erro:
                problemas.append(f"{cve}: {erro}")
                continue
            itens.append({"cve": cve, "funcoes": funcoes})
        else:
            problemas.append(f"{cve}: sem resposta em {pasta}")
    Path(saida).parent.mkdir(parents=True, exist_ok=True)  # cria patches/ se preciso
    with open(saida, "w", encoding="utf-8") as f:
        json.dump(itens, f, ensure_ascii=False, indent=2)
    print(f"{len(itens)} patches em {saida}")
    for p in problemas:
        print("  aviso:", p)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
