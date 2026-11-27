#!/usr/bin/env python3
"""Seleciona os casos do TCC: sorteio estratificado por família de CWE.

Uso (a partir da raiz do projeto):
    python3 scripts/selecionar_casos.py                          # 6 por família, semente nova
    python3 scripts/selecionar_casos.py --semente 1234           # repete um sorteio
    python3 scripts/selecionar_casos.py --semente 1234 --excluir CVE-2022-1992
    python3 scripts/selecionar_casos.py --semente 1234 --simular --saida /tmp/teste.json

Regras, nesta ordem:
  1. Família de CWE: cada caso entra na primeira família de FAMILIAS que contém
     alguma das CWEs dele (chaves de cwe_info); se nenhuma contém, "Outras".
  2. Viabilidade: só são elegíveis os casos com todas as funções vulneráveis em
     um único arquivo, no máximo 2 funções e no máximo 150 linhas vulneráveis
     no total. Casos em --excluir também deixam de ser elegíveis.
  3. Sorteio: em cada família, os elegíveis são ordenados por cve_id e
     embaralhados com random.Random(semente), uma instância por família, para
     que a ordem de uma família não dependa das outras. Os casos de --excluir
     entram no embaralhamento e são pulados depois, para que excluir um caso
     não mude a ordem sorteada.
  4. Ordem das famílias: da que tem menos repositórios elegíveis distintos para
     a que tem mais (empate: ordem da regra 1).
  5. Escolha: em cada família, na ordem sorteada, pula o candidato cujo
     repositório já está na amostra, descarta o que não tem nenhum teste
     passando na versão vulnerável (tem_testes) e escolhe os demais, até a
     família ter --por-familia casos.
  6. Vagas que sobrarem: se uma família não completar, as vagas vão para os
     elegíveis ainda não avaliados das outras famílias, juntados, ordenados por
     cve_id e embaralhados com random.Random(semente), aplicando a regra 5.
     O caso mantém a família real dele.

--excluir serve para trocar casos que falharem no teste de sanidade com a
correção oficial (pipeline com --oficial): com a mesma semente, entra o próximo
da ordem sorteada da mesma família.

--simular faz toda a seleção sem Docker, tratando todo candidato como se tivesse
testes. Serve para conferir as regras e a reprodutibilidade rapidamente.

Saídas (com --saida dados/casos.json):
  dados/casos.json           casos escolhidos, no formato do go_cases.json
                             (entrada do gerar_prompts.py e do pipeline), com o
                             campo "sorteio": {"semente", "familia", "posicao"}
  dados/casos.csv            resumo dos casos escolhidos
  dados/casos_selecao.json   registro completo da seleção, para publicar com o TCC

Imagens baixadas para casos descartados são removidas (as que já existiam antes
são mantidas). Se uma imagem não puder ser baixada, o script para em vez de
pular o caso: pular mudaria a amostra e a semente deixaria de reproduzi-la.
"""
import argparse
import csv
import json
import os
import random
import shlex
import statistics
import subprocess
import sys
from datetime import datetime
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
# reaproveita a preparação do container e a leitura do unit_test.sh do pipeline
sys.path.insert(0, str(RAIZ))
from pipeline.ambiente import alvo_dos_testes, baixar_dependencias, isolar, raiz_repo  # noqa: E402
from pipeline.conteiner import dexec  # noqa: E402
from pipeline.testes_go import parse_go_test_json  # noqa: E402

TIMEOUT_SELECAO = 600  # segundos para os testes de cada candidato
TENTATIVAS_DOWNLOAD = 3  # falhas de rede passageiras não devem mudar a amostra

# Regra 1: famílias de CWE, em ordem de prioridade. "Outras" recebe o resto.
FAMILIAS = [
    ("Caminhos e arquivos", {"CWE-22", "CWE-73"}),
    ("Injeção", {"CWE-77", "CWE-78", "CWE-89", "CWE-94"}),
    ("Controle de acesso", {"CWE-285", "CWE-862", "CWE-863", "CWE-639", "CWE-250",
                            "CWE-269", "CWE-284", "CWE-276", "CWE-732"}),
    ("Redirecionamento e requisições", {"CWE-601", "CWE-918"}),
]
OUTRAS = "Outras"
NOMES_FAMILIAS = [nome for nome, _ in FAMILIAS] + [OUTRAS]

# Regra 2: limites de viabilidade
MAX_FUNCOES = 2
MAX_LINHAS = 150


def familia(caso):
    """Regra 1: a primeira família que contém alguma CWE do caso."""
    cwes = set(caso["cwe_info"])
    return next((nome for nome, conjunto in FAMILIAS if cwes & conjunto), OUTRAS)


def linhas_vulneraveis(caso):
    return sum(int(f["end_line"]) - int(f["start_line"]) + 1 for f in caso["vul_func"])


def viavel(caso):
    """Regra 2 (sem o --excluir): um arquivo, até 2 funções, até 150 linhas."""
    return (len({f["file_path"] for f in caso["vul_func"]}) == 1
            and len(caso["vul_func"]) <= MAX_FUNCOES
            and linhas_vulneraveis(caso) <= MAX_LINHAS)


def repositorio(caso):
    """Repositório normalizado: a parte da URL depois de "github.com/", em minúsculas."""
    return caso["repo"].split("github.com/")[-1].strip("/").lower()


def sortear(casos, semente):
    """Regra 3: ordena por cve_id e embaralha com uma instância nova de Random."""
    ordem = sorted(casos, key=lambda c: c["cve_id"])
    random.Random(semente).shuffle(ordem)
    return ordem


def imagem_local(imagem):
    """True se a imagem já está baixada."""
    return subprocess.run(["docker", "image", "inspect", imagem],
                          capture_output=True).returncode == 0


def baixar_imagem(imagem):
    """Baixa a imagem, tentando de novo em caso de falha. Devolve True se baixou."""
    for _ in range(TENTATIVAS_DOWNLOAD):
        if subprocess.run(["docker", "pull", "-q", imagem], capture_output=True).returncode == 0:
            return True
    return False


def tem_testes(caso):
    """Roda os testes do unit_test.sh na versão vulnerável, sem rede.

    Devolve (bool, mensagem): True se pelo menos um teste passou.
    """
    nome = f"tcc_sel_{caso['cve_id'].lower()}"
    subprocess.run(["docker", "rm", "-f", nome], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", nome, caso["image_url"],
                    "sleep", "infinity"], capture_output=True, check=True)
    try:
        repo = raiz_repo(nome)
        baixar_dependencias(nome, repo)
        if not isolar(nome):
            return False, "não foi possível tirar o container da rede"
        pacotes = sorted({"./" + (os.path.dirname(f["file_path"]) or ".") for f in caso["vul_func"]})
        opcoes, pacotes_teste, origem = alvo_dos_testes(nome, pacotes)
        alvo = " ".join(shlex.quote(x) for x in opcoes + pacotes_teste)
        _, saida = dexec(nome, f"cd {repo} && GOPROXY=off go test -count=1 -json "
                               f"-timeout {TIMEOUT_SELECAO}s {alvo}",
                         timeout=TIMEOUT_SELECAO + 60)
        res = parse_go_test_json(saida)
        n_pass = list(res.values()).count("pass")
        msg = f"{n_pass} de {len(res)} testes passam ({origem}: {' '.join(opcoes)} {' '.join(pacotes_teste)})"
        return n_pass > 0, msg
    finally:
        subprocess.run(["docker", "rm", "-f", nome], capture_output=True)


def avaliar_testes(caso, simular):
    """Passo 5b: (tem testes?, mensagem). Com --simular, não usa Docker."""
    if simular:
        return True, "simulado (sem Docker)"
    img = caso["image_url"]
    ja_tinha = imagem_local(img)
    if not ja_tinha:
        print(f"[{caso['cve_id']}] baixando {img}...", flush=True)
        if not baixar_imagem(img):
            sys.exit(f"[{caso['cve_id']}] não foi possível baixar {img} após "
                     f"{TENTATIVAS_DOWNLOAD} tentativas. Verifique a rede e rode de novo "
                     f"com a mesma semente; pular o caso mudaria a amostra.")
    ok, msg = tem_testes(caso)
    if not ok and not ja_tinha:
        subprocess.run(["docker", "rmi", img], capture_output=True)
    return ok, msg


class Selecao:
    """Estado da seleção: a amostra, os repositórios usados e o registro dos candidatos."""

    def __init__(self, simular, posicoes, excluidos):
        self.simular = simular
        self.posicoes = posicoes  # cve_id -> posição na ordem sorteada da família
        self.excluidos = set(excluidos)  # não elegíveis: pulados sem entrar no registro
        self.escolhidos = []
        self.repos = set()
        self.avaliados = set()
        self.registro = []

    def percorrer(self, ordem, vagas, etapa):
        """Passo 5: percorre `ordem` até escolher `vagas` casos. Devolve quantos escolheu."""
        escolhidos = 0
        for caso in ordem:
            if escolhidos == vagas:
                break
            cve, fam = caso["cve_id"], familia(caso)
            if cve in self.excluidos:
                continue
            self.avaliados.add(cve)
            if repositorio(caso) in self.repos:
                resultado, rotulo, msg = "repositório repetido", "pulado", "repositório repetido"
            else:
                ok, msg = avaliar_testes(caso, self.simular)
                if ok:
                    resultado, rotulo = "escolhido", "ESCOLHIDO"
                    self.escolhidos.append(caso)
                    self.repos.add(repositorio(caso))
                    escolhidos += 1
                else:
                    resultado, rotulo = msg, "descartado"
            pos = self.posicoes[cve]
            self.registro.append({"cve_id": cve, "familia": fam, "posicao": pos,
                                  "etapa": etapa, "resultado": resultado})
            print(f"[{cve}] {fam} #{pos} {rotulo}: {msg}", flush=True)
        return escolhidos


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--casos", default=str(RAIZ / "dados" / "go_cases.json"))
    ap.add_argument("--por-familia", type=int, default=6, help="casos por família (padrão 6)")
    ap.add_argument("--saida", default=str(RAIZ / "dados" / "casos.json"))
    ap.add_argument("--semente", type=int,
                    help="semente do sorteio (sem ela, uma nova é gerada e mostrada)")
    ap.add_argument("--excluir", nargs="+", default=[], metavar="CVE",
                    help="CVEs que não podem entrar (ex.: falharam no teste de sanidade)")
    ap.add_argument("--simular", action="store_true",
                    help="selecionar sem Docker, tratando todo candidato como se tivesse testes")
    args = ap.parse_args()
    if args.por_familia < 1:
        sys.exit("--por-familia precisa ser pelo menos 1")

    casos = json.load(open(args.casos, encoding="utf-8"))
    excluidos = sorted(set(args.excluir))
    desconhecidos = sorted(set(excluidos) - {c["cve_id"] for c in casos})
    if desconhecidos:
        sys.exit(f"--excluir com CVEs que não estão em {args.casos}: {', '.join(desconhecidos)}")
    semente = args.semente if args.semente is not None else random.SystemRandom().randrange(2**32)
    print(f"Semente do sorteio: {semente} (use --semente {semente} para repetir)", flush=True)
    if args.simular:
        print("Simulação: sem Docker, todo candidato conta como tendo testes.", flush=True)

    # regras 1 a 3: famílias, elegíveis e ordem sorteada de cada família.
    # O sorteio usa os casos viáveis SEM descontar o --excluir, e os excluídos são
    # pulados ao percorrer a ordem (Selecao.percorrer). Assim, excluir um caso
    # não muda a ordem sorteada: entra o próximo da mesma família, e os que
    # vinham antes dele continuam os mesmos.
    por_familia = {nome: [c for c in casos if familia(c) == nome] for nome in NOMES_FAMILIAS}
    viaveis = {nome: [c for c in cs if viavel(c)] for nome, cs in por_familia.items()}
    elegiveis = {nome: [c for c in cs if c["cve_id"] not in excluidos]
                 for nome, cs in viaveis.items()}
    ordens = {nome: sortear(cs, semente) for nome, cs in viaveis.items()}
    posicoes = {c["cve_id"]: i for ordem in ordens.values() for i, c in enumerate(ordem, 1)}
    repos_elegiveis = {nome: len({repositorio(c) for c in cs}) for nome, cs in elegiveis.items()}

    # regra 4: da família com menos repositórios elegíveis para a com mais
    ordem_familias = sorted(NOMES_FAMILIAS,
                            key=lambda n: (repos_elegiveis[n], NOMES_FAMILIAS.index(n)))

    # regra 5
    sel = Selecao(args.simular, posicoes, excluidos)
    vagas = 0
    for nome in ordem_familias:
        print(f"\n== {nome} ({repos_elegiveis[nome]} repositórios elegíveis)", flush=True)
        vagas += args.por_familia - sel.percorrer(ordens[nome], args.por_familia, "familia")

    # regra 6
    if vagas:
        restantes = [c for cs in elegiveis.values() for c in cs if c["cve_id"] not in sel.avaliados]
        print(f"\n== Vagas que sobraram: {vagas} ({len(restantes)} elegíveis não avaliados)", flush=True)
        sel.percorrer(sortear(restantes, semente), vagas, "vagas")

    # saída: ordenada por família (ordem da regra 1) e pela ordem sorteada
    escolhidos = sorted(sel.escolhidos, key=lambda c: (NOMES_FAMILIAS.index(familia(c)),
                                                       posicoes[c["cve_id"]]))
    escolhidos = [dict(c, sorteio={"semente": semente, "familia": familia(c),
                                   "posicao": posicoes[c["cve_id"]]}) for c in escolhidos]
    saida = Path(args.saida)
    saida.parent.mkdir(parents=True, exist_ok=True)
    with open(saida, "w", encoding="utf-8") as f:
        json.dump(escolhidos, f, ensure_ascii=False, indent=2)

    caminho_csv = saida.with_suffix(".csv")
    with open(caminho_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["familia", "posicao", "cve_id", "cwes", "repo", "n_funcoes",
                    "linhas_vulneraveis", "image_url"])
        for c in escolhidos:
            w.writerow([c["sorteio"]["familia"], c["sorteio"]["posicao"], c["cve_id"],
                        ";".join(c["cwe_info"]), repositorio(c), len(c["vul_func"]),
                        linhas_vulneraveis(c), c["image_url"]])

    n_escolhidos = {n: sum(1 for c in escolhidos if c["sorteio"]["familia"] == n)
                    for n in NOMES_FAMILIAS}
    caminho_registro = saida.with_name(saida.stem + "_selecao.json")
    registro = {
        "semente": semente,
        "por_familia": args.por_familia,
        "excluidos": excluidos,
        "simulado": args.simular,
        "data_hora": datetime.now().isoformat(timespec="seconds"),
        "familias": {n: {"casos": len(por_familia[n]),
                         "elegiveis": len(elegiveis[n]),
                         "repositorios_elegiveis": repos_elegiveis[n],
                         "escolhidos": n_escolhidos[n]} for n in NOMES_FAMILIAS},
        "ordem_familias": ordem_familias,
        "candidatos": sel.registro,
    }
    with open(caminho_registro, "w", encoding="utf-8") as f:
        json.dump(registro, f, ensure_ascii=False, indent=2)

    # tabela final
    def mediana(cs):
        m = statistics.median(linhas_vulneraveis(c) for c in cs) if cs else 0
        return f"{m:g}"
    print(f"\n{'Família':32} {'Casos':>5}  {'Elegíveis (repos)':>17}  {'Mediana':>7}  {'Escolhidos':>10}")
    for n in NOMES_FAMILIAS:
        el = f"{len(elegiveis[n])} ({repos_elegiveis[n]})"
        print(f"{n:32} {len(por_familia[n]):>5}  {el:>17}  {mediana(por_familia[n]):>7}  {n_escolhidos[n]:>10}")
    total_el = sum(len(cs) for cs in elegiveis.values())
    print(f"{'Total':32} {len(casos):>5}  {total_el:>17}  {mediana(casos):>7}  {len(escolhidos):>10}")
    print(f"\nCasos em {saida}, resumo em {caminho_csv}, registro em {caminho_registro}")

    minimo = len(NOMES_FAMILIAS) * args.por_familia
    if len(escolhidos) < minimo:
        sys.exit(f"só {len(escolhidos)} casos escolhidos; o esperado era {minimo}")


if __name__ == "__main__":
    main()
