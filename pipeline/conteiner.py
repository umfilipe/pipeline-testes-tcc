"""Execução de comandos no host e dentro do container Docker do caso."""
import subprocess


def sh(cmd, timeout=None, entrada=None):
    """Roda um comando no host e devolve (código de saída, stdout + stderr).

    `cmd` é uma lista de argumentos (sem shell). Se o comando passar do
    `timeout`, devolve o código 124 (o mesmo do utilitário `timeout`) e uma
    mensagem no lugar da saída, em vez de lançar exceção.
    """
    try:
        p = subprocess.run(cmd, input=entrada, capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return 124, f"[TIMEOUT após {timeout}s]"


def dexec(nome, script, timeout=None, so_stdout=False):
    """Roda um script bash dentro do container `nome` (docker exec).

    Usa `bash -lc` para carregar o ambiente de login da imagem (PATH do Go etc.).
    Com `so_stdout=True`, descarta o stderr: útil quando a saída precisa ser
    interpretada (JSON do gosec, diff do git, conteúdo de arquivo).
    """
    cmd = ["docker", "exec", nome, "bash", "-lc", script]
    if so_stdout:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return p.returncode, p.stdout
        except subprocess.TimeoutExpired:
            return 124, ""
    return sh(cmd, timeout=timeout)
