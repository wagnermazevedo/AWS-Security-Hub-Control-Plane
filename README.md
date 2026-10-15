# AWS Security Hub as Control Plane

<p align="center">
  <a href="#-português">Português</a> •
  <a href="#-english">English</a>
</p>

---

## 🇧🇷 Português

O AWS Security Hub costuma ser usado como painel: ele mostra os problemas, alguém exporta para uma planilha, e os findings continuam abertos meses depois. Este módulo transforma o Security Hub na **fonte de verdade de um plano de controle**: ele lê os findings, confere o recurso real, decide o que fazer com cada um e fecha o ciclo corrigindo o recurso e marcando o finding como resolvido.

> **Importante:** este repositório nasce do template [AWS Security Control Plane Scripts](https://github.com/wagnermazevedo/AWS-Security-Control-Plane-Scripts) e segue o mesmo contrato de execução, a mesma estratégia de saídas e o mesmo `test-control-plane.sh`.
>
> ⚠️ **Use somente numa conta de testes.** O setup do laboratório desliga proteções da conta de propósito.

### Objetivos do Módulo

- **Security Hub como fonte de verdade**, inclusive de compliance: os padrões (AWS FSBP, CIS, NIST SP 800-53, PCI DSS) moram aqui.
- **Decisão declarativa** por ID de controle, nunca por palavra-chave no título.
- **Ciclo fechado:** corrigir o recurso e devolver o finding como `RESOLVED`, com nota de auditoria.
- **Evidência versionada** de cada execução.

### Controles cobertos

| Controle FSBP | O que verifica | Decisão | O que o apply faz |
|---|---|---|---|
| **S3.1** | Block Public Access ligado na conta | AUTO | Liga as 4 flags na conta |
| **S3.8** | Block Public Access ligado no bucket | AUTO | Liga as 4 flags no bucket |
| **EC2.2** | Security group default da VPC sem regras | AUTO | Remove as regras de entrada e saída (só em SG `default`) |
| **EC2.7** | Criptografia de EBS por padrão | AUTO | Liga na região |
| **IAM.4** | Usuário root sem access key | MANUAL | Só marca o finding `NOTIFIED`, com runbook |

O IAM.4 fica manual de propósito: nem todo finding deve ser corrigido por script, e chave de root é um deles.

### Contrato de Execução (Scan / Plan / Remediate)

1. **Scan (somente leitura):** busca os findings `FAILED`, `ACTIVE` e em `NEW` ou `NOTIFIED` dos controles do mapa. Para cada um, consulta o recurso de verdade e grava `verified_state`, porque alguns controles são reavaliados periodicamente e o finding pode estar atrasado.
2. **Plan (não muda):** cruza cada finding com o `config/remediate_map.yaml` e decide `AUTO`, `MANUAL`, `SUPPRESS` ou `NO_ACTION` (recurso já conforme).
3. **Remediate (muda, controlado):** dry-run é o padrão. No apply, busca o finding de novo, corrige o recurso, confere o novo estado e só então chama `BatchUpdateFindings` com `RESOLVED`. Itens manuais viram `NOTIFIED` e exceções viram `SUPPRESSED`, sempre com nota.

> **Regra de Ouro:** nenhuma remediação acontece acidentalmente. Em dry-run, nenhuma API de escrita é chamada, nem no recurso nem no Security Hub.

**Exceções com dono:** um bucket ou security group com a tag `scp-exception` não é corrigido nem ignorado: vira `SUPPRESSED` com a justificativa (valor da tag) e o dono (tag `exception-owner`). Exceção sem dono vira `MANUAL`.

**Leitor de formato isolado:** todo o conhecimento do ASFF está em `scanner/findings.py`. Se a fonte mudar para OCSF (Security Lake ou a nova geração do Security Hub), troca-se o leitor e o plan e o remediate continuam iguais.

### Verificação Automatizada e Testes

O `test-control-plane.sh` do template orquestra os estágios `scripts/00`, `01` e `02`, e o setup `scripts/99` cria o estado inseguro que eles testam:

1. **Provisionamento do estado inseguro:** `scripts/99_securityhub_lab_setup.py`
2. **Validação da detecção:** `scripts/00_securityhub_scan.py`
3. **Avaliação da estratégia:** `scripts/01_securityhub_plan.py`
4. **Aplicação e validação da remediação:** `scripts/02_securityhub_remediate.py` em dry-run e depois em apply, seguido de um novo scan

Os testes offline (`python3 -m unittest discover -s tests -v`) rodam o ciclo completo numa conta simulada, validam cada chamada contra o modelo oficial da API do botocore e conferem o resultado com `tests/expected_findings.yaml`.

### Implantação e Replicação via AWS CloudShell

#### Passo 1: Clonar e instalar

```bash
cd ~
git clone https://github.com/wagnermazevedo/AWS-Security-Hub-Control-Plane.git
cd AWS-Security-Hub-Control-Plane
pip3 install --user -r requirements.txt
```

#### Passo 2: Criar o laboratório (conta de testes)

```bash
python3 scripts/99_securityhub_lab_setup.py --region us-east-1
```

Liga o AWS Config, o Security Hub e o FSBP, desliga o Block Public Access da conta e a criptografia de EBS por padrão (guardando o estado anterior) e sobe o `lab_insecure/insecure-stack.yaml`. S3.8 e EC2.2 são reavaliados em minutos; S3.1 e EC2.7 são periódicos e podem levar horas, então rode o setup com antecedência.

#### Passo 3: Scan, Plan e Remediate

```bash
python3 scripts/00_securityhub_scan.py --region us-east-1
python3 scripts/01_securityhub_plan.py \
  --input-yaml outputs/<timestamp>/securityhub_findings_export.yaml \
  --rules config/remediate_map.yaml \
  --output-yaml outputs/remediation_plan.yaml
python3 scripts/02_securityhub_remediate.py --region us-east-1 --yaml outputs/remediation_plan.yaml --mode dry-run
python3 scripts/02_securityhub_remediate.py --region us-east-1 --yaml outputs/remediation_plan.yaml --mode apply
```

Ou pelo orquestrador do template, a partir do `$HOME`:

```bash
~/AWS-Security-Hub-Control-Plane/test-control-plane.sh AWS-Security-Hub-Control-Plane dry-run
```

#### Passo 4: Limpar

```bash
python3 scripts/99_securityhub_lab_setup.py --region us-east-1 --destroy
```

Remove a stack e restaura as proteções da conta ao estado de antes do setup. O Security Hub e o AWS Config continuam ligados.

### Estratégia de Saídas (Outputs)

Cada execução cria uma pasta nova em `outputs/<timestamp>/`, nunca sobrescrita:

- **YAML** (`securityhub_findings_export.yaml`): entrada do plan.
- **JSON:** fonte da verdade, com o finding ASFF bruto.
- **CSV:** pronto para o Amazon Athena.
- **Markdown** (`summary.md`): resumo para triagem.

O remediate grava JSON, CSV e Markdown, e não YAML, para que o `test-control-plane.sh` continue encontrando o YAML de scan mais recente. Se o plano tiver passado pela anonimização do orquestrador, o remediate busca a conta pela credencial em uso e os findings de novo no Security Hub, então os números mascarados não atrapalham.

### Permissões

- **Scan:** `securityhub:GetFindings`, `s3:GetAccountPublicAccessBlock`, `s3:GetBucketPublicAccessBlock`, `s3:GetBucketTagging`, `ec2:DescribeSecurityGroups`, `ec2:GetEbsEncryptionByDefault`, `iam:GetAccountSummary`, `sts:GetCallerIdentity`
- **Apply:** também `securityhub:BatchUpdateFindings`, `s3:PutAccountPublicAccessBlock`, `s3:PutBucketPublicAccessBlock`, `ec2:RevokeSecurityGroupIngress`, `ec2:RevokeSecurityGroupEgress`, `ec2:EnableEbsEncryptionByDefault`

### Estrutura do Repositório

```text
AWS-Security-Hub-Control-Plane/
├── test-control-plane.sh          # Motor de orquestração de testes do template
├── scripts/                       # Estágios que o orquestrador executa
│   ├── 00_securityhub_scan.py
│   ├── 01_securityhub_plan.py
│   ├── 02_securityhub_remediate.py
│   └── 99_securityhub_lab_setup.py   # Cria e desfaz o laboratório
├── config/remediate_map.yaml      # O cérebro: controle -> AUTO / MANUAL / SUPPRESS
├── scanner/                       # Detecção (somente leitura): leitor ASFF e estado real
├── remediate/                     # Uma função pequena por controle
├── lab_insecure/                  # CloudFormation do estado inseguro (+ atalhos deploy/destroy)
├── tests/                         # Testes offline e expected_findings.yaml
├── lib/                           # Clientes AWS e gravadores de saída
├── reports/                       # Relatórios consolidados
├── outputs/                       # Saídas versionadas (imudaveis)
└── docs/                          # Documentação
```

### Desafio da semana

Adote um controle: adicione um sexto controle ao `remediate_map.yaml` (por exemplo, o GuardDuty.1), com a função em `remediate/`, o caso no `lab_insecure/` e o teste em `tests/`, e mande um pull request.

---

## 🇺🇸 English

AWS Security Hub is usually treated as a dashboard. This module turns it into the **source of truth of a control plane**: it reads findings, checks the real resource, decides what to do with each one, and closes the loop by fixing the resource and marking the finding as resolved.

> **Important:** this repository is created from the [AWS Security Control Plane Scripts](https://github.com/wagnermazevedo/AWS-Security-Control-Plane-Scripts) template and follows the same execution contract, output strategy and `test-control-plane.sh`.
>
> ⚠️ **Use only in a test account.** The lab setup intentionally disables account protections.

### Controls

| FSBP control | Check | Decision | Apply |
|---|---|---|---|
| **S3.1** | Account-level S3 Block Public Access | AUTO | Enable all 4 flags on the account |
| **S3.8** | Bucket-level S3 Block Public Access | AUTO | Enable all 4 flags on the bucket |
| **EC2.2** | VPC default security group has no rules | AUTO | Revoke all ingress and egress rules (`default` SG only) |
| **EC2.7** | EBS encryption by default | AUTO | Enable in the region |
| **IAM.4** | Root user has no access key | MANUAL | Mark the finding `NOTIFIED` with a runbook |

### Execution Contract

1. **Scan (read-only):** fetches `FAILED`, `ACTIVE`, `NEW`/`NOTIFIED` findings for the mapped controls and records the real resource state as `verified_state`.
2. **Plan (non-mudating):** matches each finding to `config/remediate_map.yaml` by control ID and decides `AUTO`, `MANUAL`, `SUPPRESS` or `NO_ACTION`.
3. **Remediate (controlled):** dry-run by default. In apply mode it re-fetches the finding, fixes the resource, verifies it, and only then calls `BatchUpdateFindings` with `RESOLVED`. Manual items become `NOTIFIED` and owned exceptions (`scp-exception` + `exception-owner` tags) become `SUPPRESSED`.

### Quick start (AWS CloudShell)

```bash
cd ~ && git clone https://github.com/wagnermazevedo/AWS-Security-Hub-Control-Plane.git
cd AWS-Security-Hub-Control-Plane && pip3 install --user -r requirements.txt
python3 scripts/99_securityhub_lab_setup.py --region us-east-1           # lab (test account only)
~/AWS-Security-Hub-Control-Plane/test-control-plane.sh AWS-Security-Hub-Control-Plane dry-run
python3 scripts/99_securityhub_lab_setup.py --region us-east-1 --destroy # cleanup
```

### Output Strategy

Every run writes a new `outputs/<timestamp>/` folder that is never overwritten: YAML (plan input), JSON (source of truth, raw ASFF), CSV (Athena) and `summary.md`. Offline tests: `python3 -m unittest discover -s tests -v`.

### Repository Structure

Same layout as the template (`scanner/`, `remediate/`, `lab_insecure/`, `reports/`, `outputs/`, `lib/`, `docs/`), plus `scripts/` (the 00/01/02/99 stages the orchestrator runs), `config/` (the remediation map) and `tests/`.
