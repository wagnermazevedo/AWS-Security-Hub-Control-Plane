# Arquitetura

```text
 99_securityhub_lab_setup.py ──► conta de testes com S3.1, S3.8, EC2.2, EC2.7 e IAM.4 falhando
                                        │
                                        ▼
 00_securityhub_scan.py ── GetFindings (ASFF) ──► scanner/findings.py   (leitor de formato)
                        └─ estado real ───────► scanner/resources.py  (verified_state)
                                        │
                     outputs/<ts>/securityhub_findings_export.yaml
                                        │
 01_securityhub_plan.py ── config/remediate_map.yaml + controls/*.yaml ──► AUTO / MANUAL / SUPPRESS / NO_ACTION
                                        │
                              remediation_plan.yaml
                                        │
 02_securityhub_remediate.py
   ├─ busca o finding de novo (o plano pode estar velho ou anonimizado)
   ├─ AUTO: remediate/<controle>.py ► confere o recurso ► BatchUpdateFindings RESOLVED
   ├─ MANUAL: BatchUpdateFindings NOTIFIED (nota + runbook)
   └─ SUPPRESS: BatchUpdateFindings SUPPRESSED (justificativa + dono)
                                        │
                     outputs/<ts>/securityhub_remediation_results.{json,csv} + summary.md
```

## Decisões de projeto

- **Match por ID de controle** (`Compliance.SecurityControlId`), não por palavra-chave: o título de um finding muda, o ID do controle não.
- **Verificar antes e depois:** o finding diz o que o Security Hub viu na última avaliação; o `verified_state` diz como o recurso está agora.
- **Fechar o finding só depois de conferir o recurso:** corrigir sem fechar é trabalho pela metade, e fechar sem conferir é pior.
- **Recusas explícitas:** o EC2.2 só atua em security group chamado `default`; recursos anonimizados no plano são recusados com mensagem clara.
