# Pipeline de testes de patches de segurança em Go

Este pipeline avalia correções de vulnerabilidades geradas por LLMs em projetos Go
reais. Ele usa os casos em Go do **PatchEval-Verified**: cada caso é um CVE com a
função vulnerável, a correção oficial e uma imagem Docker com o repositório, os
testes e uma prova de conceito (PoC) do ataque.

Para cada patch, o pipeline responde a três perguntas:

1. **O patch corrige a vulnerabilidade?** A PoC do benchmark deixa de funcionar.
2. **O patch quebra o programa?** Compara os testes unitários (com `-race`) antes e depois do patch.
3. **O patch introduz problemas novos?** Compara os achados de `gosec` e Semgrep
   antes e depois do patch. Com qualquer achado novo, o patch nunca é aprovado automaticamente.

## Estrutura

```
├── scripts/      preparação (filtrar e sortear casos, gerar prompts, montar patches) e limpeza das imagens
├── pipeline/     o pipeline de avaliação (pacote Python)
├── dataset/      patcheval_verified.json, o dataset original do PatchEval
├── dados/        casos em Go (go_cases.*), piloto (piloto.json) e casos sorteados (casos.*)  [gerado]
├── config/       regras do Semgrep para Go (cópia local, para reprodutibilidade)
├── prompts/      um prompt por CVE, para enviar ao modelo                        [gerado]
├── respostas/    respostas dos modelos, uma pasta por modelo (respostas/<modelo>/<CVE>.md)  [fora do git]
├── patches/      patches no formato lido pelo pipeline (patches_<modelo>.json)  [gerado]
└── resultados/   saída do pipeline, uma pasta por execução                       [gerado]
```

As pastas marcadas com `[gerado]` são criadas pelos scripts e ficam fora do git
(ver `.gitignore`). Para recriá-las, siga os passos de [Como rodar](#como-rodar).
A pasta `respostas/` também fica fora do git, mas por outro motivo: o script só
cria os arquivos vazios, e as respostas são obtidas via Claude Code e Antigravity
CLI e coladas neles (passo 4). Como os resultados, elas são material de cada rodada, não código. Uma nova chamada ao
modelo não devolve o mesmo texto. Para reproduzir uma rodada, guarde uma
cópia das respostas fora do repositório (por exemplo, junto com os resultados).

O arquivo `dataset/patcheval_verified.json` é uma cópia do dataset do
[PatchEval](https://github.com/bytedance/PatchEval) (licença Apache-2.0), fixada
no commit `b43285c`, para que o projeto rode sem clonar o repositório original.
Para atualizá-lo:

```
curl -fL -o dataset/patcheval_verified.json \
    https://raw.githubusercontent.com/bytedance/PatchEval/main/patcheval/datasets/patcheval_verified.json
```

Se ele mudar, os casos selecionados em `dados/` podem mudar também.

O pacote `pipeline/` está dividido assim:

| Arquivo         | Responsabilidade                                                    |
|-----------------|---------------------------------------------------------------------|
| `__main__.py`   | linha de comando: lê os argumentos, carrega casos e patches, roda tudo |
| `avaliacao.py`  | avaliação de um caso, do container ao veredito                      |
| `patches.py`    | monta o diff a partir das funções corrigidas, baixa e filtra o diff oficial |
| `testes_go.py`  | lê a saída de `go test -json` e compara as versões                  |
| `sast.py`       | roda `gosec` e Semgrep, encontra e formata os achados novos (com a CWE) |
| `conteiner.py`  | executa comandos no host e dentro do container                      |
| `ambiente.py`   | prepara e isola o container, salva o código da PoC, lê os testes do `unit_test.sh` |
| `relatorio.py`  | grava o `resumo.csv`                                                |
| `config.py`     | timeouts e configuração padrão do Semgrep                           |

## Requisitos

- Python 3.8+ (só biblioteca padrão)
- Docker, com acesso às imagens `ghcr.io/patcheval-cve/patcheval-cve:<cve>`
- Semgrep: `pipx install semgrep`
- gosec compilado de forma **estática**, porque ele é copiado para dentro do container:
  ```
  CGO_ENABLED=0 go install github.com/securego/gosec/v2/cmd/gosec@latest
  ```
- Acesso à internet no host para baixar as imagens e, com `--oficial`, os diffs
  do GitHub. Os containers só têm rede na preparação, para baixar as dependências
  Go. Os testes, a análise e a PoC rodam **sem rede**.

## Como rodar

Execute todos os comandos a partir da raiz do projeto.

### 1. Selecionar os casos em Go

```
python3 scripts/filtrar_go.py dataset/patcheval_verified.json
```

O script grava `dados/go_cases.json`, `dados/go_cases.csv` e `dados/piloto.json`
(os 5 casos do piloto estão na lista `PILOTO`, no início do script) e mostra os
`docker pull` das imagens do piloto. O piloto serve para testar o pipeline; os
casos do TCC saem do sorteio do passo 2.

### 2. Sortear os casos do TCC

```
python3 scripts/selecionar_casos.py --simular --saida /tmp/teste.json   # confere as regras, sem Docker
python3 scripts/selecionar_casos.py                                    # seleção real, semente nova
python3 scripts/selecionar_casos.py --semente 1234                     # repete um sorteio
python3 scripts/selecionar_casos.py --semente 1234 --excluir CVE-AAAA-NNNN   # troca um caso
```

O script faz um sorteio estratificado por família de CWE, com `--por-familia`
casos (padrão 6) em cada uma das 5 famílias. As regras, na ordem:

1. **Família:** cada caso entra na primeira família que contém alguma CWE dele:
   "Caminhos e arquivos" (CWE-22, 73), "Injeção" (CWE-77, 78, 89, 94),
   "Controle de acesso" (CWE-285, 862, 863, 639, 250, 269, 284, 276, 732),
   "Redirecionamento e requisições" (CWE-601, 918) ou "Outras".
2. **Viabilidade:** só são elegíveis os casos com as funções vulneráveis em um
   único arquivo, no máximo 2 funções e no máximo 150 linhas vulneráveis.
3. **Sorteio:** em cada família, os elegíveis são ordenados por `cve_id` e
   embaralhados com a semente.
4. **Ordem das famílias:** da que tem menos repositórios elegíveis distintos para
   a que tem mais.
5. **Escolha:** na ordem sorteada, pula o caso cujo repositório já está na
   amostra e descarta o que não tem nenhum teste passando na versão vulnerável,
   sem rede. Os demais são escolhidos até completar a família.
6. **Vagas que sobrarem:** vão para os elegíveis ainda não avaliados das outras
   famílias, em um novo sorteio com a mesma semente.

Sem `--semente`, o script gera uma e a mostra no terminal. **Anote a semente**:
com ela e o mesmo `go_cases.json`, a seleção se repete. Se uma imagem não puder
ser baixada, o script para em vez de pular o caso, porque pular mudaria a amostra.

A seleção real baixa a imagem de cada candidato (cerca de 2 GB cada) e roda os
testes dele; as imagens dos casos descartados são removidas. Use `--simular`
para conferir as regras sem Docker: nesse modo, todo candidato conta como tendo
testes.

O `--excluir` serve para trocar um caso que falhar no teste de sanidade com a
correção oficial (passo 6). Rode de novo com a **mesma semente** e o CVE em
`--excluir`: entra o próximo da ordem sorteada da mesma família, e os casos que
vinham antes dele continuam os mesmos.

Saídas (com o padrão `--saida dados/casos.json`):

| Arquivo | Conteúdo |
|---|---|
| `dados/casos.json` | casos escolhidos, no formato do `go_cases.json`, com o campo `sorteio` (semente, família e posição) |
| `dados/casos.csv` | resumo dos casos escolhidos |
| `dados/casos_selecao.json` | registro da seleção: semente, parâmetros, contagens por família e o resultado de cada candidato avaliado. |

### 3. Gerar os prompts e os arquivos de resposta

```
python3 scripts/gerar_prompts.py dados/casos.json prompts/ --modelos claude-opus gemini-neon
```

Gera `prompts/<CVE>.txt`, com a descrição da falha, o código
vulnerável e o formato de resposta esperado (blocos ` ```go `). O prompt **não**
traz o identificador do CVE nem as CWEs: com eles, o modelo poderia reconhecer a
vulnerabilidade ou lembrar a correção publicada, em vez de analisar o código. O
`<CVE>` aparece só no nome do arquivo, que não é enviado ao modelo. No fim, a seção
"Entrega" pede que o modelo crie um arquivo `resposta.txt` com a resposta completa,
o que evita perder as marcações ` ```go ` ao copiar a resposta. Para cada nome em
`--modelos`, cria também `respostas/<modelo>/<CVE>.md` **vazio**, um por caso.
Arquivos de resposta que já existem não são tocados, então rodar o script de novo
não apaga respostas já coladas.

### 4. Colar as respostas do modelo

As respostas são obtidas usando o Claude Code e o Antigravity CLI:

1. Abra uma **conversa nova** para cada caso, para uma resposta não influenciar a outra.
2. Cole o conteúdo de `prompts/<CVE>.txt` e envie.
3. Copie o conteúdo do arquivo `resposta.txt` que o modelo criou e cole em
   `respostas/<modelo>/<CVE>.md`. Se o modelo não criar o arquivo, copie a
   resposta inteira mantendo os blocos ` ```go `.

O modelo e a configuração usados são anotados (por exemplo, o nível de raciocínio).

### 5. Montar o arquivo de patches

```
python3 scripts/montar_patches.py dados/casos.json respostas/claude-opus patches/patches_claude-opus.json
```

O script extrai os blocos de código Go de cada resposta e avisa quando falta uma
resposta, quando um arquivo ainda está vazio ou quando o número de blocos não bate
com o número de funções vulneráveis.
Dois tipos de bloco são descartados, porque virariam código inválido no patch:
blocos idênticos ao código vulnerável (alguns modelos citam o original antes da
correção) e blocos que não são declarações completas (`func`, `var`, `const` ou
`type`), como uma linha solta citada na explicação.

Dos blocos que sobram, cada função vulnerável recebe o **último bloco que a
declara** (mesmo nome e mesmo tipo de receptor), junto com as auxiliares que
estiverem nele, como o prompt pede. Os outros blocos ficam de fora: é comum o
modelo citar na análise uma struct que já existe no arquivo, e ela viraria uma
redeclaração no patch (`nao_compila`). Se alguma função não for encontrada pelo
nome, vale a regra por posição: com uma função vulnerável, todos os blocos
juntos; com mais, um bloco por função, na ordem.

### 6. Rodar o pipeline

Primeiro, faça o **teste de sanidade com a correção oficial**. A PoC deve ser
bloqueada em todos os casos. Se não for, o problema está no pipeline ou no caso,
e não no modelo:

```
python3 -m pipeline --casos dados/casos.json --oficial --saida resultados/oficial \
    --semgrep-config config/regras_semgrep_golang.yaml
```

Depois, avalie os patches do modelo:

```
python3 -m pipeline --casos dados/casos.json --patches patches/patches_claude-opus.json \
    --saida resultados/claude-opus --semgrep-config config/regras_semgrep_golang.yaml
```

Opções úteis:

- `--cve CVE-2020-4037 CVE-2022-1992`: avalia só os CVEs indicados.
- `--gosec CAMINHO`: binário do gosec, se ele não estiver no `PATH`.
- Sem `--semgrep-config`, o pipeline usa as regras online `p/golang`, que podem
  mudar entre execuções.
- O Semgrep roda sempre com `--no-git-ignore`. O código analisado é copiado para
  `resultados/`, que está no `.gitignore`, e sem essa opção o Semgrep pularia
  todos os arquivos sem avisar.

### 7. Liberar o espaço das imagens

Cada imagem do PatchEval ocupa cerca de 1,5 a 2,5 GB. Depois de terminar
**todas** as execuções que usam os casos (correção oficial e cada modelo),
remova as imagens:

```
python3 scripts/limpar_imagens.py dados/casos.json --simular   # mostra o que seria removido
python3 scripts/limpar_imagens.py dados/casos.json             # remove as imagens destes casos
python3 scripts/limpar_imagens.py --todas                       # remove todas as imagens do PatchEval
```

O script só remove imagens `ghcr.io/patcheval-cve/...` e containers parados do
pipeline (`tcc_*`) criados a partir delas. Outras imagens e containers do Docker
ficam intactos, e uma imagem com container em execução é pulada. Para rodar o
pipeline de novo nesses casos, as imagens são baixadas outra vez.

## O que o pipeline faz em cada caso

1. **Preparação:** sobe o container do CVE com rede, baixa as dependências Go
   (`go mod download` e, se o projeto usa `vendor/`, `go mod vendor`) e desconecta
   o container da rede. Algumas imagens não trazem todas as dependências, ou
   têm a pasta `vendor/` inconsistente, e sem isso o código nem compila.
2. **Linha de base (versão vulnerável):** os testes unitários com
   `go test -race -json` e, nos pacotes das funções vulneráveis, `gosec` e Semgrep.
   Os testes são os que o benchmark escolheu no `/workspace/unit_test.sh` da
   imagem (o `-run` e o pacote de lá). Os autores do PatchEval deixaram de fora
   testes que precisam de internet e testes que mudam de propósito com a correção,
   como os que verificavam o comportamento vulnerável.
3. **Patch:** tenta aplicar o diff com `git apply --check`. Se não houver diff, ou se
   ele não aplicar, troca as funções vulneráveis pelas corrigidas e gera o diff com o git.
4. **Versão corrigida:** `go build`, testes, `gosec` e Semgrep.
5. **Achados novos de análise estática:** se o `gosec` ou o Semgrep acusar algo que não existia na versão vulnerável, cada achado vai para
   `achados_novos.log`, com o caminho do arquivo, a linha e o código ao redor, e o
   terminal mostra o mesmo conteúdo em destaque, junto com o caminho do log. O
   pipeline **não para**: segue para a PoC e o veredito, mas o caso não pode
   receber `aprovado_automatico`.
6. **PoC:** roda `/workspace/fix-run.sh` do benchmark. Código de saída 0 significa que
   o ataque foi bloqueado.
7. **Comparação:** testes que passavam e deixaram de passar e corridas novas.
8. Remove o container.

Os achados são comparados por regra, arquivo e trecho de código, sem o número da
linha, que muda quando o patch insere ou remove código acima deles. Cada achado
traz a CWE: o `gosec` a informa direto, e no Semgrep ela vem dos metadados da
regra local (`metadata.cwe` em `config/regras_semgrep_golang.yaml`).

## Resultados

Cada execução gera `resultados/<execução>/`:

```
resumo.csv                 uma linha por caso (status e contagens)
<CVE>/resultado.json       resultado completo do caso
<CVE>/fix.patch            diff efetivamente aplicado
<CVE>/testes_base.json     resultado de cada teste na versão vulnerável
<CVE>/testes_base.log      saída completa do go test na versão vulnerável
<CVE>/testes_patch.json    resultado de cada teste na versão corrigida
<CVE>/testes_patch.log     saída completa do go test na versão corrigida
<CVE>/poc.log              saída da PoC
<CVE>/poc/                 código da PoC: fix-run.sh (script que a roda), files/ (arquivos que ele copia para o repositório) e poc_spec.json
<CVE>/achados_novos.log    achados novos do gosec/Semgrep: CWE, arquivo, linha e código (só se houver)
<CVE>/src_vulneravel/      cópia do código analisado pelo Semgrep (antes)
<CVE>/src_patch/           cópia do código analisado pelo Semgrep (depois)
```

Status possíveis (`status` em `resultado.json` e `resumo.csv`):

| Status                | Significado                                                       |
|-----------------------|-------------------------------------------------------------------|
| `erro_ambiente`       | o container não pôde ser isolado da rede (nada foi avaliado)       |
| `patch_invalido`      | não foi possível montar o diff (número de funções errado, nada mudou…) |
| `nao_aplicavel`       | `git apply --check` rejeitou o patch                              |
| `nao_compila`         | `go build` falhou após aplicar o patch                            |
| `poc_nao_bloqueada`   | a PoC ainda explora a vulnerabilidade                             |
| `regressao_funcional` | PoC bloqueada, mas algum teste quebrou ou surgiram corridas novas |
| `achados_novos`       | PoC bloqueada e sem regressão, mas o `gosec` ou o Semgrep acusou um achado novo (ver `achados_novos.log`); segue para a revisão manual |
| `aprovado_automatico` | passou em todas as verificações; segue para a revisão manual      |

Os quatro primeiros status interrompem a avaliação, porque sem um patch aplicado
e compilado não há o que testar. Depois do `go build`, todas as etapas rodam
sempre, e o status é o da primeira falha da tabela. Por exemplo, um patch que não
bloqueia a PoC e também tem achados novos fica com `poc_nao_bloqueada`. Mesmo
assim, `achados_novos.log` é criado e os achados aparecem no terminal e no
`resultado.json` (`gosec_novos`, `semgrep_novos`).

O aviso `sem_testes_executaveis_na_base` indica que nenhum teste passava na versão
vulnerável, então não é possível detectar regressões nesse caso.

A **revisão manual** acontece nos casos `aprovado_automatico` e `achados_novos`,
os dois em que a PoC foi bloqueada e nenhum teste quebrou:

| Status | O que revisar |
|---|---|
| `aprovado_automatico` | Se a correção ataca a causa raiz e não só a forma de ataque da PoC, se preserva o comportamento esperado e se não introduz fraquezas que as ferramentas não detectam |
| `achados_novos` | Tudo o que se revisa no `aprovado_automatico` e, além disso, cada achado do `achados_novos.log`, classificado como fraqueza secundária, mitigação ilusória (suspeita) ou falso positivo/padrão herdado (ver [Achados novos de análise estática](#achados-novos-de-análise-estática)) |

Os demais status já são reprovações automáticas e não seguem para a revisão manual.

## Como interpretar os resultados

### Regressão funcional: testes quebrados e corridas novas

O status `regressao_funcional` indica que o patch bloqueou o ataque, mas quebrou o
comportamento esperado do programa. São duas verificações, as duas feitas
executando os testes do benchmark antes e depois do patch:

| Verificação | Campo no `resultado.json` | O que significa | Como é detectada |
|---|---|---|---|
| Testes quebrados | `testes_quebrados` (lista) | Testes que **passavam** na versão vulnerável e **falham** depois do patch: a correção mudou um comportamento que os desenvolvedores esperavam | Compara o resultado de cada teste em `testes_base.json` e `testes_patch.json` |
| Testes que já falhavam | `testes_ja_falhavam` (lista) | Testes que falhavam **já antes** do patch. Não contam como regressão, porque o problema não foi causado pelo patch | Mesma comparação |
| Corridas novas | `corridas_base`, `corridas_patch` (contagens) | Condições de corrida (*data races*) que surgiram com o patch: duas goroutines acessam a mesma variável ao mesmo tempo, pelo menos uma escreve, e não há sincronização (mutex, canal). O resultado passa a depender da ordem de execução, e o bug aparece de forma intermitente | Os testes rodam com `go test -race`; conta os avisos `WARNING: DATA RACE` antes e depois. Se o número aumenta, há corridas novas |

O detector de corridas só acusa corridas que de fato acontecem durante os testes.
Uma corrida num trecho que nenhum teste exercita passa despercebida.

### Achados novos de análise estática

As duas ferramentas analisam o código sem executá-lo, mas procuram coisas diferentes:

| Ferramenta | O que procura | Exemplos |
|---|---|---|
| `gosec` | Problemas de segurança específicos de Go, com CWE associada | Erro ignorado (G104), permissão de arquivo ou diretório frouxa (G301), caminho de arquivo vindo de entrada externa (G304) |
| Semgrep | Padrões inseguros descritos nas regras de `config/regras_semgrep_golang.yaml` | Uso inseguro de criptografia, SQL montado com entrada externa, TLS sem versão mínima |

Um achado novo impede o `aprovado_automatico`, mas é só um **alarme
automático**: as ferramentas têm falsos positivos, e a comparação entre versões é
mecânica. A classificação final de cada achado é manual:

| Classificação | Quando usar | Exemplo |
|---|---|---|
| Fraqueza secundária | O achado é real e aponta uma fraqueza **diferente** da do CVE (outra CWE), introduzida pelo próprio patch. É o encaixe mais comum | O patch corrige um path traversal (CWE-22), mas remove um arquivo sem checar o erro (G104, CWE-703) |
| Mitigação ilusória (suspeita) | O achado é da **mesma CWE** do CVE e fica no trecho corrigido ou no mesmo fluxo de dados: indício de que a vulnerabilidade continua explorável por outro caminho, mesmo com a PoC bloqueada. Só se confirma com análise manual ou outra PoC | O patch de um path traversal (CWE-22) ainda tem um G304 (caminho vindo de entrada externa) na função corrigida |
| Falso positivo ou padrão herdado | O achado não é um problema real, ou repete um padrão que o projeto já usava (inclusive na correção oficial) | O patch cria um diretório com `os.MkdirAll(..., 0755)` (G301), igual ao resto do projeto |

Um achado de análise estática **não** é regressão funcional: ele não diz se o
programa continua funcionando, só que o código tem um padrão suspeito. Regressão
funcional é medida pelos testes, como na tabela anterior.

Registre a classificação de cada achado na análise manual. Assim também dá para
medir a precisão do alarme: quantos achados eram problemas reais.

## Resultados da rodada piloto (2026-11-26)

Primeira rodada com o critério de seleção do TCC (passo 2) e com os prompts sem
o identificador do CVE e sem as CWEs (passo 3).

**Configuração**

| Item | Valor |
|---|---|
| Seleção | `scripts/selecionar_casos.py --por-familia 1` (1 caso por família, 5 no total), semente `3037737912` |
| Modelos | Claude Opus 5.5 (`claude-opus`) e Gemini Argon (`gemini-argon`), os dois com **effort high** |
| Coleta | via Claude Code e Antigravity CLI, uma conversa nova por caso |
| Regras do Semgrep | `config/regras_semgrep_golang.yaml` |

Na seleção, dois candidatos foram descartados por não terem nenhum teste
passando na versão vulnerável: CVE-2023-24623 (1º de "Redirecionamento e
requisições") e CVE-2025-29778 (1º de "Controle de acesso"). O registro completo
está em `dados/casos_selecao.json`.

**Resultado** (`resultados/<execução>/resumo.csv`)

| Família | CVE | Projeto | Oficial | Claude Opus 5.5 | Gemini Argon |
|---|---|---|---|---|---|
| Caminhos e arquivos | CVE-2020-29529 | hashicorp/go-slug | `aprovado_automatico` | `aprovado_automatico` | `aprovado_automatico` |
| Injeção | CVE-2024-27289 | jackc/pgx | `aprovado_automatico` | `aprovado_automatico` | `aprovado_automatico` |
| Controle de acesso | CVE-2025-24976 | distribution/distribution | `aprovado_automatico` | `aprovado_automatico` | `regressao_funcional` |
| Redirecionamento e requisições | CVE-2020-4037 | oauth2-proxy/oauth2-proxy | `aprovado_automatico` | `aprovado_automatico` | `poc_nao_bloqueada` |
| Outras | CVE-2025-48374 | project-zot/zot | `aprovado_automatico` | `aprovado_automatico` | `aprovado_automatico` |
| **Aprovados automaticamente** | | | **5/5** | **5/5** | **3/5** |

Nenhum caso teve achado novo de `gosec` ou Semgrep, nem corridas novas. A
correção oficial (teste de sanidade) passou nos 5 casos, então nenhum caso
precisou ser trocado com `--excluir`.

**Falhas do Gemini Argon**

- **CVE-2020-4037 (`poc_nao_bloqueada`):** o patch só troca `?` por `*` na regex
  `invalidRedirectRegex`, o que bloqueia vários espaços entre as barras, mas não
  o caminho com ponto. A PoC ainda redireciona com `/./\evil.com` e
  `/./../../\evil.com`. A correção oficial trata também esse caso. A resposta do
  modelo começa com "Análise da Vulnerabilidade (CVE-2020-11053 /
  GHSA-j7px-6hwj-hp4g)": sem o identificador no prompt, ele reconheceu o código e
  aplicou a correção de um CVE anterior do mesmo trecho. É um indício de
  correção memorizada, e não de análise do código.
- **CVE-2025-24976 (`regressao_funcional`):** `TestTokenVerify` e `TestLeeway`
  passaram a falhar com "untrusted JWK with no certificate chain". O patch
  rejeita chaves JWK sem cadeia de certificados, que o comportamento esperado
  aceita.

**Pendências:** revisão manual dos 8 casos `aprovado_automatico` dos modelos.
Esta rodada tem 1 caso por família e serve para validar o processo; os números
não permitem comparar os modelos.
