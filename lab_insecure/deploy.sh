#!/bin/bash
# Atalho para o setup do laboratório (scripts/99_securityhub_lab_setup.py). Conta de testes, sempre.
DIR="$(cd "$(dirname "$0")/.." && pwd)"
python3 "$DIR/scripts/99_securityhub_lab_setup.py" --region "${AWS_REGION:-us-east-1}" "$@"
