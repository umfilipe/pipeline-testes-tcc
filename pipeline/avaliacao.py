"""Avaliação completa de um caso (um CVE e o patch proposto para ele).

Status possíveis no resultado (campo "status"), na ordem em que são checados.
Os quatro primeiros interrompem a avaliação, porque sem patch aplicado e
compilado não há o que testar; a partir daí, todas as etapas rodam sempre:
  erro_ambiente        -> o container não pôde ser isolado da rede (nada foi avaliado)
  patch_invalido       -> não foi possível montar o diff a partir das funções
  nao_aplicavel        -> `git apply --check` rejeitou o patch
  nao_compila          -> `go build` falhou após aplicar o patch
  poc_nao_bloqueada    -> a PoC do benchmark ainda explora a vulnerabilidade
  regressao_funcional  -> PoC bloqueada, mas algum teste quebrou ou surgiram corridas novas
  achados_novos        -> PoC bloqueada e sem regressão, mas o gosec ou o Semgrep
                          acusou algo que não existia na versão vulnerável;
                          segue para a revisão manual, junto com os achados
  aprovado_automatico  -> passou em tudo; segue para a revisão manual

Sempre que houver achado novo (qualquer que seja o status), o caso ganha o
achados_novos.log com o arquivo, a linha e o código de cada achado.
"""
import json
import os
import shlex
import time

from .ambiente import alvo_dos_testes, baixar_dependencias, isolar, raiz_repo, salvar_poc
from .config import TIMEOUT_POC, TIMEOUT_TESTES
from .conteiner import dexec, sh
from .patches import montar_patch_por_funcoes
from .sast import achados_novos, formatar_achados, rodar_gosec, rodar_semgrep
from .testes_go import comparar_testes, contar_corridas, parse_go_test_json


def avaliar(caso, item, args, pasta):
    """Avalia o patch `item` para o `caso` e devolve o dicionário de resultado.

    `args` são os argumentos da linha de comando (usa `args.gosec` e
    `args.semgrep_config`). Os artefatos intermediários (testes, patch, log da
    PoC, código da PoC, cópias do código) são gravados em `pasta`.
    """
    cve = caso["cve_id"]
    # nome único do container, para não colidir com execuções anteriores
    nome = f"tcc_{cve.lower()}_{int(time.time())}"
    r = {"cve": cve, "cwes": list(caso["cwe_info"]), "status": None}
    t0 = time.time()
    # remove o log de uma execução anterior na mesma pasta, para não mostrar
    # achados que não são desta execução
    (pasta / "achados_novos.log").unlink(missing_ok=True)
    # sobe o container COM rede só para a preparação; `sleep infinity` o mantém
    # vivo para os docker exec
    sh(["docker", "run", "-d", "--name", nome, caso["image_url"], "sleep", "infinity"])
    try:
        repo = raiz_repo(nome)

        # ---- preparação (única etapa com rede): baixa as dependências Go
        cod, out = baixar_dependencias(nome, repo)
        if cod != 0:
            # segue mesmo assim: o cache da imagem pode bastar
            r["aviso_preparacao"] = out[-1000:]
        # ---- a partir daqui, tudo roda sem rede
        if not isolar(nome):
            r["status"], r["erro"] = "erro_ambiente", "não foi possível tirar o container da rede"
            return r

        # código da PoC, para a revisão manual; salvo aqui para existir mesmo se o
        # patch não aplicar ou não compilar. Falhar na cópia não afeta o veredito
        erro = salvar_poc(nome, pasta / "poc")
        if erro:
            r["aviso_poc"] = f"código da PoC não foi salvo por completo ({erro})"

        # pacotes Go que contêm as funções vulneráveis: build e SAST rodam neles
        arquivos = sorted({f["file_path"] for f in caso["vul_func"]})
        pacotes = sorted({"./" + (os.path.dirname(a) or ".") for a in arquivos})
        r["pacotes"] = pacotes
        sh(["docker", "cp", args.gosec, f"{nome}:/tmp/gosec"])
        lista = " ".join(pacotes)

        # testes de regressão: os escolhidos pelo benchmark no unit_test.sh
        opcoes, pacotes_teste, origem = alvo_dos_testes(nome, pacotes)
        r["testes_alvo"] = {"origem": origem, "opcoes": opcoes, "pacotes": pacotes_teste}
        alvo = " ".join(shlex.quote(x) for x in opcoes + pacotes_teste)

        def teste_cmd(race):
            # -count=1 desliga o cache de testes; -race ativa o detector de corridas
            return (f"cd {repo} && GOPROXY=off go test {'-race ' if race else ''}-count=1 -json "
                    f"-timeout {TIMEOUT_TESTES}s {alvo}")

        # ---- versão vulnerável (linha de base)
        race = True
        _, tb = dexec(nome, teste_cmd(race), timeout=TIMEOUT_TESTES + 60)
        base = parse_go_test_json(tb)
        if not base and ("requires cgo" in tb or "C compiler" in tb):
            # imagem sem compilador C: o -race não funciona, roda sem ele
            race = False
            r["aviso_race"] = "detector de corridas indisponível (sem cgo)"
            _, tb = dexec(nome, teste_cmd(race), timeout=TIMEOUT_TESTES + 60)
            base = parse_go_test_json(tb)
        (pasta / "testes_base.log").write_text(tb)
        (pasta / "testes_base.json").write_text(json.dumps(base, indent=1))
        r["testes_base"] = {s: list(base.values()).count(s) for s in ("pass", "fail", "skip")}
        if r["testes_base"]["pass"] == 0:
            # nenhum teste passa na versão vulnerável: não há como detectar regressão
            r["aviso"] = "sem_testes_executaveis_na_base"
        r["corridas_base"] = contar_corridas(tb)
        gosec_base, _ = rodar_gosec(nome, repo, pacotes)
        semgrep_base, _ = rodar_semgrep(nome, repo, pacotes, pasta / "src_vulneravel",
                                        args.semgrep_config)

        # ---- patch
        def preparar(patch):
            """Salva o patch, copia para o container e verifica se aplica (sem aplicar)."""
            (pasta / "fix.patch").write_text(patch)
            sh(["docker", "cp", str(pasta / "fix.patch"), f"{nome}:/workspace/fix.patch"])
            return dexec(nome, f"cd {repo} && git apply --check --whitespace=nowarn /workspace/fix.patch")

        cod, out = 1, "sem patch"
        if "fix_patch" in item:
            # 1ª opção: diff pronto
            cod, out = preparar(item["fix_patch"])
            r["origem_patch"] = "diff"
        if cod != 0 and item.get("funcoes"):
            # 2ª opção (diff ausente ou não aplicável): troca as funções vulneráveis
            erro_diff = out if "fix_patch" in item else None
            patch, erro = montar_patch_por_funcoes(nome, repo, caso, item["funcoes"])
            if erro:
                r["status"], r["erro"] = "patch_invalido", erro
                return r
            cod, out = preparar(patch)
            r["origem_patch"] = "funcoes"
            if erro_diff:
                r["erro_diff_original"] = erro_diff[-2000:]
        if cod != 0:
            r["status"], r["erro"] = "nao_aplicavel", out[-2000:]
            return r
        # o --check passou: aplica de fato e compila
        dexec(nome, f"cd {repo} && git apply --whitespace=nowarn /workspace/fix.patch")
        cod, out = dexec(nome, f"cd {repo} && GOPROXY=off go build {lista}", timeout=TIMEOUT_TESTES)
        if cod != 0:
            r["status"], r["erro"] = "nao_compila", out[-2000:]
            return r

        # ---- versão corrigida
        _, td = dexec(nome, teste_cmd(race), timeout=TIMEOUT_TESTES + 60)
        (pasta / "testes_patch.log").write_text(td)
        depois = parse_go_test_json(td)
        (pasta / "testes_patch.json").write_text(json.dumps(depois, indent=1))
        r["testes_quebrados"], r["testes_ja_falhavam"] = comparar_testes(base, depois)
        r["corridas_patch"] = contar_corridas(td)
        gosec_depois, _ = rodar_gosec(nome, repo, pacotes)
        semgrep_depois, _ = rodar_semgrep(nome, repo, pacotes, pasta / "src_patch",
                                          args.semgrep_config)
        r["gosec_novos"] = achados_novos(gosec_base, gosec_depois)
        r["semgrep_novos"] = achados_novos(semgrep_base, semgrep_depois)
        r["gosec_total"] = {"base": len(gosec_base), "patch": len(gosec_depois)}
        r["semgrep_total"] = {"base": len(semgrep_base), "patch": len(semgrep_depois)}
        novos = {"gosec": r["gosec_novos"], "semgrep": r["semgrep_novos"]}
        tem_achados = any(novos.values())
        if tem_achados:
            # não para: grava o log (arquivo, linha e código de cada achado) e
            # segue para a PoC; o achado só impede o aprovado_automatico
            (pasta / "achados_novos.log").write_text(formatar_achados(novos, pasta / "src_patch"))

        # ---- PoC (o fix-run.sh detecta que o patch já está aplicado)
        # código de saída 0 = a PoC não conseguiu explorar a vulnerabilidade
        cod, poc = dexec(nome, "cd /workspace && bash fix-run.sh", timeout=TIMEOUT_POC)
        (pasta / "poc.log").write_text(poc)
        r["poc_bloqueada"] = cod == 0

        # ---- veredito
        regressao = bool(r["testes_quebrados"]) or r["corridas_patch"] > r["corridas_base"]
        if not r["poc_bloqueada"]:
            r["status"] = "poc_nao_bloqueada"
        elif regressao:
            r["status"] = "regressao_funcional"
        elif tem_achados:
            r["status"] = "achados_novos"  # nunca aprova com achado novo
        else:
            r["status"] = "aprovado_automatico"  # segue para a revisão manual
        return r
    finally:
        # roda mesmo nos retornos antecipados e em exceções: registra o tempo e remove o container
        r["segundos"] = round(time.time() - t0)
        sh(["docker", "rm", "-f", nome])
