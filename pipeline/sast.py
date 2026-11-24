"""Análise estática (SAST) com gosec e Semgrep e comparação dos achados.

Cada achado vira um dicionário com regra, CWE, arquivo, linha, trecho de código
normalizado e severidade. Para comparar a versão vulnerável com a corrigida,
a chave usada ignora o número da linha (ver `achados_novos`).
"""
import json
import os
import re
import shutil
from pathlib import Path

from .config import SEMGREP_OPCOES, TIMEOUT_TESTES
from .conteiner import dexec, sh


def normalizar(txt):
    """Junta espaços em branco repetidos, para comparar trechos de código
    sem depender de indentação ou quebras de linha."""
    return re.sub(r"\s+", " ", txt).strip()


def linha_do_arquivo(caminho, n):
    """Devolve a linha `n` (contando a partir de 1) do arquivo, ou "" se não existir."""
    try:
        with open(caminho, encoding="utf-8", errors="replace") as f:
            for i, l in enumerate(f, 1):
                if i == n:
                    return l
    except OSError:
        pass
    return ""


def chaves_gosec(saida_json, raiz_repo):
    """Converte a saída JSON do gosec em uma lista de achados.

    Devolve (achados, erro); `erro` é "saida_invalida" se o JSON não puder ser lido.
    """
    try:
        dados = json.loads(saida_json)
    except json.JSONDecodeError:
        return [], "saida_invalida"
    chaves = []
    for it in dados.get("Issues") or []:
        # caminho relativo à raiz do repositório, para bater entre as duas versões
        arq = os.path.relpath(it.get("file", ""), raiz_repo)
        # o gosec pode informar um intervalo ("12-15"); fica só a primeira linha
        inicio = str(it.get("line", "0")).split("-")[0]
        # o campo "code" traz algumas linhas no formato "N: código";
        # pega o código da linha em que o achado começa
        trecho = ""
        for l in (it.get("code") or "").splitlines():
            m = re.match(r"\s*(\d+):\s?(.*)", l)
            if m and m.group(1) == inicio:
                trecho = m.group(2)
        chaves.append({"regra": it.get("rule_id"), "cwe": (it.get("cwe") or {}).get("id"),
                       "arquivo": arq, "linha": inicio, "trecho": normalizar(trecho),
                       "severidade": it.get("severity")})
    return chaves, None


def cwes_semgrep(resultado):
    """CWEs de um achado do Semgrep, tiradas dos metadados da regra.

    As regras locais (config/regras_semgrep_golang.yaml) trazem, em
    metadata.cwe, uma lista de textos como "CWE-327: Use of a Broken or Risky
    Cryptographic Algorithm", e o Semgrep repassa esses metadados no JSON de
    cada achado. Devolve (números, descrições): ["327"] e o texto completo.
    """
    cwes = resultado.get("extra", {}).get("metadata", {}).get("cwe") or []
    if isinstance(cwes, str):  # algumas regras usam um texto só, não uma lista
        cwes = [cwes]
    numeros = [m.group(1) for c in cwes for m in [re.match(r"\s*CWE-(\d+)", c)] if m]
    return numeros, [c.strip() for c in cwes]


def chaves_semgrep(saida_json, raiz_local):
    """Converte a saída JSON do Semgrep em uma lista de achados.

    Devolve (achados, erro); `erro` é "saida_invalida" se o JSON não puder ser lido.
    """
    try:
        dados = json.loads(saida_json)
    except json.JSONDecodeError:
        return [], "saida_invalida"
    chaves = []
    for r in dados.get("results") or []:
        caminho = r.get("path", "")
        n = r.get("start", {}).get("line", 0)
        # sem login, o Semgrep omite o texto da linha; lemos do arquivo copiado
        trecho = linha_do_arquivo(caminho, n)
        # CWE no mesmo formato do gosec (só o número); uma regra pode ter mais de
        # uma, e aí os números vêm separados por vírgula ("327, 328")
        numeros, descricoes = cwes_semgrep(r)
        chaves.append({"regra": r.get("check_id"), "cwe": ", ".join(numeros) or None,
                       "cwe_descricao": descricoes,
                       "arquivo": os.path.relpath(caminho, raiz_local),
                       "linha": str(n), "trecho": normalizar(trecho),
                       "severidade": r.get("extra", {}).get("severity")})
    return chaves, None


def achados_novos(base, depois):
    """Achados presentes após o patch e ausentes na versão vulnerável.

    A chave é (regra, arquivo, trecho) e ignora o número da linha, que muda
    quando o patch insere ou remove código acima do achado.
    """
    def k(a):
        return (a["regra"], a["arquivo"], a["trecho"])
    vistos = {k(a) for a in base}
    return [a for a in depois if k(a) not in vistos]


def rodar_gosec(nome, repo, pacotes):
    """Roda o gosec dentro do container sobre os pacotes afetados.

    O binário do gosec é copiado para /tmp/gosec antes (ver avaliacao.py); por
    isso ele precisa ser compilado de forma estática (CGO_ENABLED=0), já que a
    imagem do container pode ter outra libc. GOPROXY=off impede tentativas de
    baixar módulos (o container não tem rede). -no-fail evita código de saída
    diferente de zero quando há achados.
    """
    alvo = " ".join(p.rstrip("/") + "/..." for p in pacotes)
    cod, out = dexec(nome, f"cd {repo} && GOPROXY=off /tmp/gosec -fmt=json -quiet -no-fail {alvo} 2>/dev/null",
                     timeout=TIMEOUT_TESTES, so_stdout=True)
    return chaves_gosec(out, repo)


def rodar_semgrep(nome, repo, pacotes, destino, config):
    """Copia os diretórios analisados do container para `destino` no host e
    roda o Semgrep sobre eles com a configuração `config`.

    O Semgrep roda no host (e não no container) porque as imagens do
    benchmark não o têm instalado e não têm rede para instalá-lo. A cópia
    fica salva em `destino` (src_vulneravel/ ou src_patch/) para consulta.
    """
    # começa de uma pasta limpa para não misturar com execuções anteriores
    if destino.exists():
        shutil.rmtree(destino)
    destino.mkdir(parents=True)
    for p in pacotes:
        rel = p.lstrip("./")
        (destino / rel).parent.mkdir(parents=True, exist_ok=True)
        sh(["docker", "cp", f"{nome}:{repo}/{rel}", str(destino / rel)])
    # SEMGREP_OPCOES inclui --no-git-ignore (ver config.py): o Semgrep nunca
    # considera o .gitignore, senão pularia a cópia em resultados/
    cod, out = sh(["semgrep", "scan", "--config", config, *SEMGREP_OPCOES, str(destino)],
                  timeout=TIMEOUT_TESTES)
    # a saída pode ter avisos antes do JSON; descarta tudo antes do primeiro "{"
    inicio = out.find("{")
    return chaves_semgrep(out[inicio:] if inicio >= 0 else "", str(destino))


def localizar(copia, arquivo):
    """Caminho de `arquivo` (relativo à raiz do repositório) dentro da cópia
    `copia` (src_vulneravel/ ou src_patch/).

    Quando o pacote está na raiz do repositório, o docker cp grava a cópia numa
    subpasta com o nome do repositório (copia/<repo>/arquivo.go); por isso, se o
    caminho direto não existir, procura um arquivo cujo caminho termine igual.
    """
    direto = copia / arquivo
    if direto.is_file():
        return direto
    return next((c for c in copia.rglob(Path(arquivo).name)
                 if c.as_posix().endswith(arquivo)), direto)


def formatar_achados(novos, src_patch, contexto=2):
    """Monta o texto do achados_novos.log: um bloco por achado novo, com a
    ferramenta, a regra, o caminho do arquivo e a linha, e o código ao redor.

    `novos` é {ferramenta: lista de achados}. O caminho mostrado é o da cópia da
    versão corrigida em `src_patch` (a mesma que o Semgrep analisou), para
    abrir o arquivo direto na linha do achado.
    """
    blocos = []
    for ferramenta, achados in novos.items():
        for a in achados:
            n = int(a["linha"] or 0)
            arq = localizar(src_patch, a["arquivo"])
            cab = f"[{ferramenta}] {a['regra']}"
            if a.get("cwe"):
                # "327, 328" -> "(CWE-327, CWE-328)"
                cab += " (" + ", ".join(f"CWE-{c}" for c in a["cwe"].split(", ")) + ")"
            if a.get("severidade"):
                cab += f" severidade={a['severidade']}"
            linhas = [cab, f"  arquivo: {arq}:{n}"]
            for d in a.get("cwe_descricao") or []:  # só o Semgrep traz o nome da CWE
                linhas.append(f"  cwe: {d}")
            # trecho do arquivo ao redor da linha do achado, com ">" na linha apontada
            for i in range(max(1, n - contexto), n + contexto + 1):
                texto = linha_do_arquivo(arq, i)
                if texto:
                    linhas.append(f"  {'>' if i == n else ' '} {i:5d} | {texto.rstrip()}")
            blocos.append("\n".join(linhas))
    return "\n\n".join(blocos) + "\n"
