# Como adicionar um controle novo: GuardDuty.1

O GuardDuty.1 pede que o GuardDuty esteja habilitado na conta e na região. É um controle de conta (não tem bucket nem security group), então ele segue o mesmo padrão do S3.1 e do EC2.7.

Todos os caminhos abaixo são relativos a `~/AWS-Security-Hub-Control-Plane`.

---

## Passo 1: crie o arquivo do controle

Crie `config/controls/GuardDuty.1.yaml`:

```yaml
id: GuardDuty.1
title: "GuardDuty habilitado na conta"
decision: AUTO
action: guardduty_enable_detector
severity: HIGH
```

O `include: - controls/*.yaml` do `config/remediate_map.yaml` já carrega o arquivo novo sozinho. Para desligar o controle sem apagar o arquivo, adicione `enabled: false`.

## Passo 2: ensine o scanner a verificar o recurso

Em `scanner/resources.py`, crie a função de verificação e registre no `VERIFIERS`:

```python
def guardduty_enabled(clients, account_id: str, locator=None) -> State:
    gd = clients["guardduty"]
    detectors = gd.list_detectors().get("DetectorIds", [])
    if not detectors:
        return NONCOMPLIANT, {"detectors": 0}
    status = gd.get_detector(DetectorId=detectors[0]).get("Status")
    return (COMPLIANT if status == "ENABLED" else NONCOMPLIANT), {"detectorId": detectors[0], "status": status}


VERIFIERS = {
    ...
    "GuardDuty.1": guardduty_enabled,
}
```

## Passo 3: escreva a correção (só para AUTO)

Crie `remediate/guardduty_1.py`. Em dry-run, nenhuma API de escrita é chamada:

```python
"""GuardDuty.1: cria (ou reativa) o detector do GuardDuty na região."""


def run(clients, ctx, dry_run):
    gd = clients["guardduty"]
    detectors = gd.list_detectors().get("DetectorIds", [])
    change = {"api": "guardduty:UpdateDetector" if detectors else "guardduty:CreateDetector"}
    if dry_run:
        return {"ok": True, "message": "DRY-RUN: habilitaria o GuardDuty nesta região", "changes": [change]}
    if detectors:
        gd.update_detector(DetectorId=detectors[0], Enable=True)
    else:
        gd.create_detector(Enable=True)
    return {"ok": True, "message": "OK: GuardDuty habilitado", "changes": [change]}
```

E registre a ação em `remediate/__init__.py`, com o mesmo nome usado no `action:` do passo 1:

```python
from remediate.guardduty_1 import run as guardduty_enable_detector

REGISTRY = {
    ...
    "guardduty_enable_detector": guardduty_enable_detector,
}
```

## Passo 4: libere o serviço novo

Em `lib/aws.py`, adicione `"guardduty"` ao `SERVICES`:

```python
SERVICES = ("securityhub", "s3", "s3control", "ec2", "iam", "sts", "guardduty")
```

Para que o scan e o apply funcionem, sua role precisa de `guardduty:ListDetectors`, `guardduty:GetDetector`, `guardduty:CreateDetector` e `guardduty:UpdateDetector`.

## Passo 5: recurso ou conta?

O GuardDuty.1 é um controle de conta, então aqui não há nada a fazer. Se o controle novo fosse de um recurso (por exemplo uma tabela do DynamoDB), você ajustaria `resource_locator` em `scanner/findings.py` e `resource_tags` em `scanner/resources.py`, para o scanner saber qual recurso é e ler as tags de exceção.

## Passo 6: laboratório e testes

1. No `scripts/99_securityhub_lab_setup.py` (configurações de conta) ou no `lab_insecure/insecure-stack.yaml` (recursos), deixe o GuardDuty desligado no deploy e garanta que o `--destroy` desfaz o que o apply ligou.
2. Em `tests/fakes.py`, crie um `FakeGuardDuty` (com `list_detectors`, `get_detector`, `create_detector` e `update_detector`), adicione-o ao `SERVICES` dos fakes e inclua um finding falso:
   ```python
   _finding("GuardDuty.1", "AwsAccount", f"AWS::::Account:{ACCOUNT}", "HIGH"),
   ```
3. Em `tests/expected_findings.yaml`, adicione:
   ```yaml
   - control: GuardDuty.1
     verified_state: noncompliant
     decision: AUTO
     workflow_after_apply: RESOLVED
   ```
4. Rode os testes:
   ```bash
   cd ~
   python3 -m unittest discover -s ~/AWS-Security-Hub-Control-Plane/tests -v
   ```

## Passo 7: rode o ciclo

```bash
cd ~
python3 ~/AWS-Security-Hub-Control-Plane/scripts/00_securityhub_scan.py --region us-east-1
python3 ~/AWS-Security-Hub-Control-Plane/scripts/01_securityhub_plan.py
python3 ~/AWS-Security-Hub-Control-Plane/scripts/02_securityhub_remediate.py --mode dry-run
python3 ~/AWS-Security-Hub-Control-Plane/scripts/02_securityhub_remediate.py --mode apply
```

Se o arquivo tiver um ID repetido, ou um controle AUTO sem `action`, o scan e o plan param com erro antes de qualquer mudança.

> Atenção: o GuardDuty passa a ser cobrado depois dos 30 dias de teste grátis. Em uma Organization, prefira habilitar pelo administrador delegado.

---
