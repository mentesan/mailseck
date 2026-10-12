# CLAUDE.md (raiz do repositório)

Só o que é específico deste código. Convenções gerais (KISS, POSIX, segurança, testes, formatação, limite de
colunas, idioma de comentários) vêm do `~/.claude/CLAUDE.md` de nível de usuário e não se repetem aqui.

## Contexto do repositório

- Autor: Fabio Almeida
- Licença: BSD 3-Clause License
- Módulo: `github.com/mentesan/mailseck`
- Versão de Go: a diretiva `go` do `go.mod` é a fonte (hoje 1.26)
- Natureza: ferramenta CLI de análise de SPF e DMARC para exposição a spoofing de e-mail; requisitos em `PRD.md`
- Consumidores: humano no terminal (saída texto) e automação (saída `--json` e código de saída), incluindo um
  workflow n8n de mapeamento de superfície de ataque externa
- Compatibilidade retroativa: campo novo no JSON é livre; renomear ou remover campo, mudar valor de `status` ou
  de `code` de achado, ou mudar o significado de um código de saída é mudança de contrato e precisa estar
  declarada no ticket e refletida no README

## Gate de homologação

`make check` é o gate único: verde nele é condição de entrega. `make test-integration` depende de DNS real e
fica fora do gate; quando o ticket pedir, rode e reporte o resultado à parte.

## Estrutura de pacotes existente

`package main` na raiz (flags, validação de entrada, orquestração, código de saída) e pacotes nomeados pela
função em `internal/`:

- `cidr`: faixas publicadas de provedores de nuvem, busca concorrente e cache em disco com TTL
- `spf`: resolução e caminhada recursiva da cadeia include/redirect, contagem de lookups (RFC 7208)
- `dmarc`: resolução e parsing do registro em `_dmarc.<domínio>` (RFC 7489)
- `lookup`: classificação do resultado de uma consulta DNS em `found`, `not_found` ou `error`
- `report`: achados com `code` estável, sugestão de DMARC e renderização texto/JSON

Toda dependência externa ao processo (DNS, HTTP dos provedores) entra por interface ou por injeção em `run`
(`dependencies`), para que a suíte sem tag `integration` rode sem rede.

## Dependências fixadas

Nenhuma. O `go.mod` não tem `require` e isso é requisito (PRD §11). Dependência nova só com justificativa no
ticket e decisão registrada.

## Decisões de arquitetura específicas deste repositório

- Ausência de registro é resultado, não erro. Cada verificação carrega `status` (`found`, `not_found`,
  `error`), `is_present` e `error`; a classificação vive só em `internal/lookup`.
- NXDOMAIN e NODATA são os dois `not_found`: o resolver da stdlib devolve o mesmo `*net.DNSError` com
  `IsNotFound` para ambos, e distinguir exigiria cliente DNS próprio ou dependência externa.
- Código de saída: `0` sem achado crit, `1` com achado crit, `2` falha. `2` com relatório em stdout significa
  que uma consulta terminou em `error`; `2` sem relatório significa entrada inválida.
- Coleções no JSON nunca são `null`, sempre `[]`. Automação casa achados por `code`, nunca por `title`.
- Ciclo de include/redirect é detectado só no caminho atual da recursão, não no conjunto de hosts já vistos:
  dois ramos que incluem o mesmo host (diamante) são legítimos.
- Fornecedores de e-mail de primeira parte (Microsoft 365, Google Workspace, Amazon SES) são confiáveis pelo
  nome do host de include, não por faixa de IP, porque as faixas mudam com frequência e uma lista de IPs
  envelhece em silêncio.
- A sugestão de DMARC aperta até `quarantine`, nunca direto para `reject`, e não é emitida quando a consulta
  DMARC terminou em `error`.

## Débito técnico conhecido

- Falha de consulta em alvo de include/redirect, inclusive prazo expirado durante a consulta, vai para
  `IrresolvableHosts` (achado crit de hostname não resolvido), não para status `error`.
- Comparação de `p=` e `sp=` com `none` diferencia maiúsculas; tag `p` ausente é lida como política ativa.
- `pct` fora de 0 a 100 é aceito sem validação.
- A chave do detector de ciclo não normaliza maiúsculas nem ponto final do nome.
- A linha de erro de consulta no stderr repete o prefixo `lookup <nome>` que o erro do Go já traz.
