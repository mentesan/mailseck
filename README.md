# mailseck

Verificador de condições de spoofing de email via análise de registros
SPF e DMARC de um domínio, escrito em Go sem dependências externas.

Reimplementação, com correções de robustez e escopo ampliado, da lógica
de detecção descrita em
[Email-Spoof-Check](https://github.com/CyberCX-STA/Email-Spoof-Check)
(CyberCX, 2022). Ver [PRD.md](PRD.md) para o levantamento completo de
requisitos, arquitetura e roadmap.

## Status

Em desenvolvimento inicial (v1.0 ainda não implementada). Apenas o
esqueleto do projeto existe neste momento.

## Estrutura

```
mailseck/
  main.go                 // ponto de entrada do CLI
  internal/
    spf/                  // parsing e recursão de registros SPF
    dmarc/                // parsing de registros DMARC
    cidr/                 // CIDRs públicos de provedores de nuvem
    report/                // modelo de achados e renderizadores
```

## Build

```
go build ./...
```

## Licença

BSD 3-Clause. Ver [LICENSE](LICENSE).