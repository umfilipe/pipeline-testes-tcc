"""Preparação do container do caso e leitura dos scripts do benchmark.

Cada imagem do PatchEval traz, em /workspace:
  fix-run.sh    -> aplica /workspace/fix.patch e roda a PoC (sai com 0 se o ataque falhar);
  poc/          -> código da PoC (testes Go que o fix-run.sh copia para o repositório);
  unit_test.sh  -> aplica o patch e roda os testes unitários escolhidos pelos autores
                   do benchmark (`go test -run '^(TesteA|TesteB)$' <pacote>`).

Os testes do unit_test.sh são os que valem como verificação de regressão: os
autores do benchmark deixaram de fora testes que precisam de internet ou que
mudam de propósito com a correção (por exemplo, testes que verificavam o
comportamento vulnerável).
"""
import re
import shlex
import shutil

from .config import GOPROXY_PREPARACAO, TIMEOUT_TESTES
from .conteiner import dexec, sh

# opções do `go test` que recebem um valor no argumento seguinte
_OPCOES_COM_VALOR = {"-run", "-skip", "-timeout", "-count", "-tags", "-p", "-parallel",
                     "-bench", "-cpu", "-coverprofile", "-covermode", "-coverpkg",
                     "-exec", "-o", "-benchtime", "-shuffle", "-failfast"}
# opções que repassamos ao nosso `go test` (as demais o pipeline define sozinho)
_OPCOES_REPASSADAS = {"-run", "-skip", "-tags"}


def raiz_repo(nome):
    """Raiz do repositório no container: o primeiro `cd /workspace/...` do fix-run.sh."""
    _, run_sh = dexec(nome, "cat /workspace/fix-run.sh", so_stdout=True)
    m = re.search(r"^cd (/workspace/\S+)", run_sh, re.M)
    return m.group(1) if m else "/workspace"


def baixar_dependencias(nome, repo):
    """Baixa os módulos Go do projeto enquanto o container ainda tem rede.

    Algumas imagens não trazem todas as dependências no cache, ou têm a pasta
    vendor/ inconsistente com o go.mod (o próprio fix-run.sh delas roda
    `go mod vendor`). Sem isso, o código nem compila depois que a rede é cortada.
    Devolve (código, saída).
    """
    script = (f"cd {repo} && export GOPROXY={GOPROXY_PREPARACAO} && "
              f"go mod download && "
              # se o projeto usa vendor/, regenera a pasta a partir do go.mod
              f"if [ -d vendor ]; then go mod vendor; fi")
    return dexec(nome, script, timeout=TIMEOUT_TESTES)


def isolar(nome):
    """Desconecta o container de todas as redes. Devolve True se ficou sem rede."""
    _, redes = sh(["docker", "inspect", "-f",
                   "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}", nome])
    for rede in redes.split():
        sh(["docker", "network", "disconnect", "-f", rede, nome])
    # confere: sem rede, nenhuma interface além da loopback deve ter endereço
    _, depois = sh(["docker", "inspect", "-f",
                    "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}", nome])
    return not depois.strip()


def salvar_poc(nome, destino):
    """Copia do container para `destino`, no host, o código da PoC e o script que a roda.

    `destino` fica com o fix-run.sh e o conteúdo de /workspace/poc. Devolve uma
    mensagem com o que não pôde ser copiado, ou None se deu tudo certo.
    """
    # começa de uma pasta limpa para não misturar com execuções anteriores
    if destino.exists():
        shutil.rmtree(destino)
    destino.mkdir(parents=True)
    erros = []
    # "poc/." copia o conteúdo da pasta, e não a pasta em si
    for origem in ("/workspace/fix-run.sh", "/workspace/poc/."):
        cod, out = sh(["docker", "cp", f"{nome}:{origem}", str(destino)])
        if cod != 0:
            erros.append(f"{origem}: {out.strip()}")
    return "; ".join(erros) or None


def alvo_dos_testes(nome, pacotes_padrao):
    """Lê o `go test` do /workspace/unit_test.sh e devolve (opções, pacotes, origem).

    `opções` é uma lista como ["-run", "^(TesteA)$"]; `pacotes` são os pacotes
    (caminhos de import ou ./dir) testados. Se o script não existir ou não tiver
    um `go test`, usa todos os testes de `pacotes_padrao`.
    """
    _, script = dexec(nome, "cat /workspace/unit_test.sh 2>/dev/null", so_stdout=True)
    linhas = [l for l in script.splitlines() if "go test" in l and not l.lstrip().startswith("#")]
    if not linhas:
        return [], pacotes_padrao, "todos_os_testes_do_pacote"
    # pega o comando a partir de "go test" (a linha pode começar com "cd x &&")
    comando = linhas[-1][linhas[-1].index("go test"):]
    tokens = shlex.split(comando)[2:]
    opcoes, pacotes = [], []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t.startswith("-"):
            chave, _, valor = t.partition("=")
            if not valor and chave in _OPCOES_COM_VALOR and i + 1 < len(tokens):
                i += 1
                valor = tokens[i]
            if chave in _OPCOES_REPASSADAS:
                opcoes += [chave, valor]
        else:
            pacotes.append(t)
        i += 1
    return opcoes, pacotes or pacotes_padrao, "unit_test.sh"
