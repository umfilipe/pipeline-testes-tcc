"""Preparação dos patches avaliados pelo pipeline.

Um patch pode chegar de duas formas (ver __main__.py):
  - como um diff pronto ("fix_patch");
  - como uma lista de funções corrigidas ("funcoes"), na mesma ordem de
    `vul_func` do caso. Nesse caso, `montar_patch_por_funcoes` troca as
    funções no código do container e gera o diff com o git.

Para o teste de sanidade (--oficial), o diff vem do commit de correção no
GitHub (`baixar_patch_oficial`), com `funcoes_oficiais` como alternativa.
"""
import re
import shlex
import tempfile
import urllib.request
from pathlib import Path

from .conteiner import dexec, sh


def montar_patch_por_funcoes(nome, repo, caso, funcoes):
    """Troca cada função vulnerável pela versão nova e gera o diff com o git.

    Devolve (diff, erro). O repositório do container é restaurado no fim
    (`git checkout -- .`), então o patch ainda precisa ser aplicado depois.
    """
    if len(funcoes) != len(caso["vul_func"]):
        return None, f"esperava {len(caso['vul_func'])} funções, recebeu {len(funcoes)}"
    # agrupa as trocas por arquivo, para editar cada arquivo uma vez só
    por_arquivo = {}
    for vf, nova in zip(caso["vul_func"], funcoes):
        por_arquivo.setdefault(vf["file_path"], []).append((vf, nova))
    with tempfile.TemporaryDirectory() as tmp:
        for arq, trocas in por_arquivo.items():
            # traz o arquivo do container para o host
            local = Path(tmp) / "arq.go"
            cod, out = sh(["docker", "cp", f"{nome}:{repo}/{arq}", str(local)])
            if cod != 0:
                return None, f"não achei {arq} no container"
            texto = local.read_text(encoding="utf-8")
            # substitui de baixo para cima para não deslocar as linhas das trocas seguintes
            for vf, nova in sorted(trocas, key=lambda t: -int(t[0]["start_line"])):
                trecho = vf["snippet"]
                if texto.count(trecho) == 1:
                    # caminho preferido: o trecho vulnerável aparece exatamente uma vez
                    texto = texto.replace(trecho, nova.rstrip("\n") + ("\n" if trecho.endswith("\n") else ""))
                else:
                    # trecho ausente ou repetido: recorre ao intervalo de linhas do dataset
                    linhas = texto.splitlines(keepends=True)
                    a, b = int(vf["start_line"]) - 1, int(vf["end_line"])
                    linhas[a:b] = [nova.rstrip("\n") + "\n"]
                    texto = "".join(linhas)
            # devolve o arquivo editado ao container
            local.write_text(texto, encoding="utf-8")
            sh(["docker", "cp", str(local), f"{nome}:{repo}/{arq}"])
    # gera o diff e desfaz as edições, deixando o repositório como estava.
    # Restrito aos arquivos editados: a preparação pode ter mexido em outros
    # (vendor/modules.txt, go.sum), e essas mudanças não fazem parte do patch.
    alvos = " ".join(shlex.quote(a) for a in por_arquivo)
    cod, diff = dexec(nome, f"cd {repo} && git diff -- {alvos} && git checkout -- {alvos}",
                      so_stdout=True)
    if not diff.strip():
        return None, "o patch não alterou nada"
    return diff, None


def filtrar_diff(diff):
    """Mantém só os arquivos .go de código (sem *_test.go, go.mod, docs etc.).

    Testes da correção oficial ficam de fora para não mexer na linha de base;
    go.mod/go.sum ficam de fora porque o container não tem rede para baixar módulos.
    """
    # quebra o diff em blocos, um por arquivo, cada um começando em "diff --git"
    blocos = re.split(r"(?m)^(?=diff --git )", diff)
    mantidos = []
    for b in blocos:
        m = re.match(r"diff --git a/(\S+) b/(\S+)", b)
        if m and m.group(2).endswith(".go") and not m.group(2).endswith("_test.go"):
            mantidos.append(b)
    return "".join(mantidos)


def funcoes_oficiais(caso):
    """Para cada função vulnerável, o trecho de fix_func no mesmo arquivo que mais se
    sobrepõe a ela (em linhas).

    Usado quando o diff do GitHub não aplica porque o PatchEval já incorporou à
    imagem as partes da correção que não são de segurança. Devolve None se
    alguma função vulnerável não tiver correspondente no mesmo arquivo.
    """
    escolhidas = []
    for vf in caso["vul_func"]:
        a, b = int(vf["start_line"]), int(vf["end_line"])
        candidatos = [f for f in caso["fix_func"] if f["file_path"] == vf["file_path"]]
        if not candidatos:
            return None

        def score(f):
            # critério principal: número de linhas em comum com a função vulnerável;
            # desempate: a que começa mais perto dela
            fa, fb = int(f["start_line"]), int(f["end_line"])
            return (max(0, min(b, fb) - max(a, fa) + 1), -abs(fa - a))
        escolhidas.append(max(candidatos, key=score)["snippet"])
    return escolhidas


def baixar_patch_oficial(caso):
    """Baixa o diff do(s) commit(s) de correção no GitHub (patch_url + .diff).

    Devolve (diff, erro). O diff já sai filtrado por `filtrar_diff`.
    Esta é a única etapa que usa a rede, e ela roda no host, não no container.
    """
    partes = []
    for url in caso["patch_url"]:
        try:
            with urllib.request.urlopen(url.rstrip("/") + ".diff", timeout=60) as r:
                partes.append(r.read().decode("utf-8", errors="replace"))
        except Exception as e:  # noqa: BLE001 - qualquer falha de rede vira mensagem de erro
            return None, f"{url}: {e}"
    diff = filtrar_diff("".join(partes))
    return (diff, None) if diff.strip() else (None, "diff sem arquivos .go de código")
