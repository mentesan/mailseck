# PRD — mailseck v1.0

Verificador de condições de spoofing de email via análise de SPF e
DMARC, reimplementado em Go a partir da análise da ferramenta de
referência [Email-Spoof-Check](https://github.com/CyberCX-STA/Email-Spoof-Check)
(CyberCX, 2022, Python).

## 0. Premissas assumidas

Estas premissas foram adotadas para poder entregar uma PRD precisa sem
bloquear em perguntas de baixo impacto. Revise antes de aprovar:

- Go 1.22 ou superior (requisito mínimo real é 1.18, por causa de
  `net/netip`; 1.22 é o piso recomendado para runtime DNS/HTTP mais
  robusto).
- Binário único `mailseck`, distribuído como módulo Go standalone.
  Caminho do módulo (`github.com/mentesan/mailseck`) fica em aberto até
  a criação do repositório remoto.
- Uso individual/CI (scan de um domínio por execução). Scan em lote é
  roadmap, não v1.0.
- Sem requisito de compatibilidade com o script Python original: não
  há reuso de código, apenas reimplementação da lógica de detecção
  descrita a seguir.

## 1. Análise da ferramenta de referência

O script (`email_spoof_check.py`, ~200 linhas) faz, nesta ordem:

1. Carrega (ou atualiza via `--refresh-ips`) um cache local
   `IPs.txt` com CIDRs publicamente registráveis de GCP, AWS (EC2),
   Azure, DigitalOcean e OracleCloud, mais CIDRs custom via `-c`.
2. Resolve o TXT record do domínio, filtra a entrada `v=spf1` e
   percorre recursivamente `include:`/`redirect=` seguindo a cadeia
   de SPF, imprimindo a árvore.
3. Para cada mecanismo `ip4:`, soma o total de IPs permitidos e
   verifica se o CIDR faz overlap com algum CIDR de nuvem pública
   (indicando que um terceiro poderia alugar aquele IP e enviar
   email "autorizado" pelo SPF), ignorando uma lista fixa de falsos
   positivos.
4. Resolve o TXT `_dmarc.<domain>` e extrai `p=`, `sp=`, `pct=`.
5. Emite um relatório colorido (ANSI) com achados: ausência de SPF,
   volume de IPs permitidos, número de lookups DNS, hosts
   irresolvíveis, ausência de `-all`, overlap com nuvem pública,
   ausência de DMARC, `pct<100`, `p=none`, `sp=none`.

### 1.1 Falhas identificadas no legado (não repetir na v1.0)

- **Recursão sem limite de profundidade**: `RecurseSPF` segue todo
  `include`/`redirect` encontrado sem checar o teto de 10 lookups
  durante a recursão (só reporta o excesso _depois_, se sobreviver).
  Um SPF cíclico (`a.com` inclui `b.com` inclui `a.com`) causa
  recursão infinita e crash por stack overflow. Isto é uma falha de
  robustez com superfície de DoS trivial de acionar (basta apontar a
  ferramenta para um domínio malicioso ou mal configurado).
- **Contagem de lookups incompleta**: RFC 7208 §4.6.4 conta
  `include`, `a`, `mx`, `ptr`, `exists` e `redirect` para o limite de
  10 lookups. O script só conta `include`/`redirect`. Um SPF que
  abusa de `a`/`mx`/`exists` pode ultrapassar o limite real do RFC
  sem o script perceber, gerando falso "OK".
- **Mecanismo `ip6:` ignorado por completo**: nem contabilizado, nem
  checado contra overlap de nuvem pública. Domínios com SPF
  dual-stack têm a metade IPv6 do risco nunca avaliada.
- **Saída não é script-friendly**: cores ANSI fixas e uso de `\r`
  para progresso poluem qualquer captura em pipeline/CI; não há
  modo `--json` para consumo automatizado.
- **Sem exit code semântico**: o script sempre retorna 0, então não
  dá para usar como gate de CI (`mail linter` que nunca falha o
  build não tem valor de gate).
- **Dependência de scraping frágil**: a URL do JSON de CIDRs do
  Azure não é fixa (nome de arquivo com data, ex.:
  `ServiceTags_Public_<YYYYMMDD>.json`); o script já contorna isso
  raspando a página de download, e essa fragilidade permanece
  inerente à fonte, não ao código. Confirmado por busca: a página
  oficial (`microsoft.com/en-us/download/details.aspx?id=56519`)
  não expõe link direto estável.
- **Dependência `ipaddr` (PyPI)**: é a lib legada de Python 2,
  hoje coberta pelo `ipaddress` da stdlib. Não é um problema para o
  port em Go, mas confirma que a base de código não recebe
  manutenção ativa de dependências.
- **Sem testes**: qualquer regressão na lógica de parsing de SPF
  passa despercebida.
- **Sem licença declarada** no repositório upstream (confirmado via
  API do GitHub: `license: null`). A reimplementação em Go deve
  ser código autoral novo, baseado apenas na lógica documentada
  publicamente (algoritmo de detecção, não expressão literal do
  código-fonte). Recomendo creditar a ferramenta original como
  inspiração no README, por transparência, sem copiar trechos.

## 2. Objetivo do produto

Fornecer um binário Go, sem dependências externas, que analisa SPF e
DMARC de um domínio e reporta objetivamente se o domínio está exposto
a spoofing de email, com saída apta tanto para humano (terminal)
quanto para automação (`--json`, exit code semântico).

## 3. Casos de uso

- Analista de segurança auditando a postura de email de um domínio
  antes de um pentest ou durante hardening.
- Gate de CI/CD que falha o pipeline de infraestrutura se um domínio
  gerenciado por Terraform/Ansible perder proteção DMARC/SPF.
- Consumo por um agente de IA (via `--json`) que agrega achados de
  múltiplos domínios num relatório maior.

## 4. Escopo v1.0

### 4.1 Em escopo

**RF-01** — Resolver e validar sintaxe básica do domínio informado
(`--domain`/`-d`), rejeitando entradas que não sejam hostname válido
(RFC 1035) antes de qualquer consulta DNS.

**RF-02** — Resolver o TXT record do domínio e localizar o registro
`v=spf1`, com timeout configurável por consulta (default 5s).

**RF-03** — Seguir recursivamente `include:` e `redirect=`,
respeitando o teto de 10 lookups do RFC 7208 §4.6.4, contando
corretamente `include`, `a`, `mx`, `ptr`, `exists` e `redirect` como
consumidores de lookup (correção do bug do legado). A recursão aborta
e reporta `permerror` assim que o teto é ultrapassado, eliminando o
vetor de recursão infinita.

**RF-04** — Contabilizar IPs permitidos para mecanismos `ip4:` e
`ip6:` (paridade dual-stack, ausente no legado), usando `net/netip`
para representar e comparar prefixos.

**RF-05** — Detectar overlap entre CIDRs do SPF e CIDRs
publicamente registráveis de GCP, AWS (EC2), Azure, DigitalOcean e
OracleCloud, mais CIDRs custom (`--custom-ip`, repetível), com lista
de falsos positivos conhecida e documentada (não mais um array mágico
sem explicação: cada entrada da lista de FP carrega um comentário
com a razão).

**RF-06** — Cache local dos CIDRs de nuvem (`$XDG_CACHE_HOME` ou
equivalente por SO) com TTL de 24h por padrão, configurável via
`--cache-ttl`, e invalidação forçada via `--refresh-ips`. Busca dos 5
provedores em paralelo (limitado por `errgroup`/`WaitGroup`); falha
de um provedor gera warning e degrada a checagem daquele provedor sem
abortar o comando inteiro.

**RF-07** — Resolver o TXT `_dmarc.<domain>` e extrair `p=`, `sp=`,
`pct=`, `rua=`/`ruf=` (extração de `rua`/`ruf` é nova: relevante para
saber se há visibilidade de relatórios agregados, sinal de maturidade
da política).

**RF-08** — Gerar relatório com os mesmos achados do legado
(ausência de SPF/DMARC, volume de IPs, lookups, host irresolvível,
ausência de `-all`, overlap com nuvem pública, `pct<100`, `p=none`,
`sp=none`), mais os novos achados do dual-stack IPv6 e do
recount de lookups.

**RF-09** — Dois renderizadores de saída a partir do mesmo modelo de
dados interno: texto legível (cor via ANSI somente se stdout for TTY,
detectável e desativável com `--no-color`) e `--json` (schema estável,
pensado para consumo por scripts/agentes).

**RF-10** — Exit code semântico: `0` nenhum achado crítico, `1`
achado crítico presente (spoofável), `2` erro de execução (DNS,
rede, entrada inválida).

### 4.2 Fora de escopo v1.0 (roadmap, ver seção 10)

- Scan em lote de múltiplos domínios numa execução.
- Expansão de `a:`/`mx:` para o conjunto real de IPs (v1.0 conta o
  lookup corretamente, mas não resolve o IP resultante para checar
  overlap; é o próximo passo natural, adiado por complexidade de
  resolução em cascata A/MX).
- BIMI, MTA-STS, TLS-RPT, checagem de DKIM.
- Modo servidor/API HTTP.
- Métricas Prometheus/OpenTelemetry.
- Suporte a DNSSEC / validação de assinatura de zona.

## 5. Requisitos não funcionais

**RNF-01 (Segurança)** — Toda consulta DNS e requisição HTTP usa
`context.Context` com timeout; nenhuma chamada de rede é bloqueante
sem prazo. Validação de entrada do domínio antes de qualquer syscall
de rede. Nenhuma execução de shell, nenhuma interpolação de string do
usuário em comando externo.

**RNF-02 (Confiabilidade)** — Falha de uma fonte de CIDR de nuvem não
derruba o comando; é reportada como warning isolado. Recursão de SPF
é sempre limitada e determinística (sem possibilidade de loop
infinito, coberto por RF-03).

**RNF-03 (Portabilidade)** — Zero dependências de módulo Go externas
na v1.0. Todo o trabalho (DNS via `net.Resolver`, CIDR via
`net/netip`, HTTP via `net/http`, cache via `encoding/json` +
`os.UserCacheDir`) é coberto pela stdlib. Reduz superfície de
supply-chain a zero e elimina drift de versão de dependência.

**RNF-04 (Observabilidade)** — Logs de diagnóstico (não o relatório
em si) em `log/slog` estruturado, para stderr, nunca misturado ao
relatório principal em stdout. Isso já deixa o binário pronto para
ingestão por pipeline de observabilidade sem refactor futuro.

**RNF-05 (Testabilidade)** — Toda dependência de I/O externo (DNS,
HTTP) é abstraída por interface (`Resolver`, `CIDRProvider`),
permitindo testes unitários com fakes determinísticos, sem rede real
no `go test` padrão. Testes de integração (com rede real) ficam
isolados sob build tag (`//go:build integration`).

## 6. Interface de linha de comando

```
mailseck -d example.com [flags]

  -d, --domain string        domínio a analisar (obrigatório)
  -c, --custom-ip strings    CIDR adicional a tratar como spoofável
                              (repetível)
      --refresh-ips          força atualização do cache de CIDRs de
                              nuvem, ignorando o TTL
      --cache-ttl duration   validade do cache de CIDRs (padrão 24h)
      --timeout duration     timeout por consulta DNS/HTTP (padrão 5s)
      --json                 emite o relatório em JSON em vez de texto
      --no-color             desativa cores ANSI mesmo em TTY
  -h, --help                 ajuda
```

Saída de texto vai para stdout; logs de diagnóstico vão para stderr;
exit code conforme RF-10.

## 7. Arquitetura proposta

Estrutura de diretórios, plana o quanto der, dividida apenas onde a
coesão pede:

```
mailseck/
  main.go                 // parsing de flags, orquestração, exit code
  internal/
    spf/
      spf.go               // parsing e recursão do registro SPF
      spf_test.go
    dmarc/
      dmarc.go             // parsing do registro DMARC
      dmarc_test.go
    cidr/
      cidr.go              // interface CIDRProvider + cache
      gcp.go
      aws.go
      azure.go
      digitalocean.go
      oraclecloud.go
      cidr_test.go
    report/
      report.go            // modelo de dados do relatório
      text.go               // renderizador texto/ANSI
      json.go               // renderizador JSON
      report_test.go
  go.mod
  README.md
  PRD.md
```

Cada provedor de CIDR isolado em arquivo próprio, atrás da mesma
interface, é o que permite a fonte instável do Azure quebrar e ser
corrigida sem tocar nos outros quatro provedores nem no motor de SPF.

### 7.1 Interfaces centrais

```go
// Resolver abstrai a resolução DNS usada pelo motor de SPF/DMARC,
// permitindo substituição por um fake nos testes.
type Resolver interface {
    LookupTXT(ctx context.Context, host string) ([]string, error)
}

// CIDRProvider abstrai uma fonte de CIDRs publicamente registráveis.
type CIDRProvider interface {
    Name() string
    Fetch(ctx context.Context) ([]netip.Prefix, error)
}
```

`main.go` monta o grafo de dependências (resolver real, provedores
reais) e injeta nos pacotes `spf`/`dmarc`/`cidr`; os testes desses
pacotes injetam fakes. Não há variável global mutável em nenhum
pacote, conforme diretriz do projeto.

### 7.2 Fluxo de execução

1. `main` valida flags e domínio (RF-01).
2. `cidr.Load` retorna prefixos de nuvem (cache ou fetch, RF-06).
3. `spf.Analyze` resolve e percorre a árvore SPF (RF-02 a RF-05),
   retornando um `spf.Result` estruturado.
4. `dmarc.Analyze` resolve e faz parsing do DMARC (RF-07).
5. `report.Build` combina os dois resultados no modelo de achados
   (RF-08).
6. Renderizador de texto ou JSON escreve em stdout (RF-09); `main`
   traduz achados críticos em exit code (RF-10).

## 8. Modelo de dados (esboço)

```go
// Finding é um achado individual do relatório, com severidade fixa
// em três níveis para manter o parsing por consumidores automatizados
// simples.
type Finding struct {
    Severity Severity `json:"severity"` // info | warn | crit
    Title    string   `json:"title"`
    Detail   string   `json:"detail"`
}

// Report é o resultado completo de uma análise, serializável para
// JSON e para o renderizador de texto.
type Report struct {
    Domain   string    `json:"domain"`
    SPF      SPFResult `json:"spf"`
    DMARC    DMARCResult `json:"dmarc"`
    Findings []Finding `json:"findings"`
}
```

## 9. Estratégia de testes

- **Unitários (table-driven)**: parsing de mecanismos SPF (`ip4`,
  `ip6`, `include`, `redirect`, `a`, `mx`, `ptr`, `exists`,
  qualificadores `+`/`-`/`~`/`?`); parsing de DMARC (`p`, `sp`, `pct`,
  `rua`, `ruf`); detecção de overlap de CIDR; contagem de lookups
  incluindo caso de excesso (>10) e caso de ciclo (`a` inclui `b`
  inclui `a`, deve abortar sem estourar pilha).
- **Segurança**: fuzzing (`go test -fuzz`) do parser de SPF/DMARC
  contra entrada adversarial (TXT record malformado, mecanismo com
  macro `%{...}`, profundidade de recursão maliciosa).
  Validação de que domínio com caracteres de controle ou excesso de
  tamanho é rejeitado antes da resolução DNS.
- **Integração** (build tag `integration`, sem rede mockada): roda
  contra domínios reais conhecidos (ex.: um domínio de teste com SPF
  e DMARC publicados pelo próprio projeto) para validar o caminho
  real de resolução DNS. Não roda no `go test` padrão de CI rápido.
- Meta de cobertura: pacotes `spf` e `dmarc` (lógica de maior risco)
  acima de 90%; `cidr` e `report` acima de 80%.

## 10. Riscos e mitigação

| Risco                                                     | Impacto                                                           | Mitigação                                                                                   |
| --------------------------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Fonte de CIDR do Azure muda formato de página             | Provedor Azure falha silenciosamente                              | Isolado por `CIDRProvider`; falha não derruba o comando (RNF-02); alerta em log estruturado |
| Fontes de CIDR (Oracle, DigitalOcean) mudam URL sem aviso | Mesma classe de risco acima                                       | Mesma mitigação; cada provedor testável isoladamente                                        |
| Cache de CIDR desatualizado mascara nova faixa de nuvem   | Falso negativo em overlap                                         | TTL padrão de 24h; `--refresh-ips` para forçar                                              |
| Domínio malicioso com SPF cíclico                         | DoS por recursão infinita (bug presente no legado)                | Teto de 10 lookups aplicado durante a recursão, não só no relatório final (RF-03)           |
| Ausência de licença no projeto de referência              | Risco de disputa de propriedade intelectual se código for copiado | Reimplementação autoral, sem cópia literal; atribuição no README                            |

## 11. Critérios de aceite (Definition of Done v1.0)

- Todos os RF-01 a RF-10 implementados e cobertos por teste.
- `go vet`, `gofmt -l` e `go test ./...` limpos.
- Zero dependências externas no `go.mod` (`require` vazio além da
  versão de Go).
- `mailseck -d <domínio sem SPF/DMARC>` retorna exit code 1 e ambos
  os renderizadores (texto e `--json`) reportam os achados críticos
  esperados.
- `mailseck -d <domínio com SPF cíclico simulado via fake resolver>`
  termina em tempo finito com achado de erro, sem estourar pilha.
- README cobrindo instalação, flags, exemplos de uso e formato do
  JSON.
- Cada pacote com comentário de pacote; cada identificador exportado
  com comentário de documentação em frase completa.

## 12. Métricas de sucesso pós-lançamento

- Tempo de execução p95 abaixo de 3s para um domínio com SPF de
  profundidade típica (1-3 includes).
- Zero incidentes de recursão infinita ou timeout não tratado
  reportados em uso real.
- Adoção como gate de CI mensurável pela presença de exit code != 0
  em pipelines que o utilizam (sinal indireto de que virou dependência
  operacional, não só ferramenta ad hoc).

## 13. Roadmap racional pós-v1.0

**v1.1** — Expansão de `a:`/`mx:` para IPs reais (resolve a
lacuna deixada conscientemente fora do v1.0) e scan em lote
(`--domain-file`), reaproveitando o mesmo `Report` por domínio.

**v1.2** — Checagem de BIMI e MTA-STS/TLS-RPT, mesmo padrão de
`Finding` já criado no v1.0, sem mudança de arquitetura.

**v2.0** — Modo servidor (`cmd/mailseckd`, binário separado que
reaproveita `internal/spf`, `internal/dmarc`, `internal/cidr` sem
duplicar lógica) expondo API para consumo por agentes de IA ou
pipelines de segurança contínua; métricas Prometheus/OpenTelemetry
sobre volume de scans e distribuição de severidade dos achados.

A divisão em `internal/` desde a v1.0 é o que torna o v2.0 viável sem
reescrita: o servidor futuro é só mais um consumidor dos mesmos
pacotes, nunca uma cópia da lógica.
