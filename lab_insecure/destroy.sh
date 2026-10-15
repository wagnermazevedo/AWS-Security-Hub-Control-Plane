#!/bin/bash
# Atalho para desfazer o laboratório e restaurar as proteções da conta.
DIR="$(cd "$(dirname "$0")/.." && pwd)"
python3 "$DIR/scripts/99_securityhub_lab_setup.py" --region "${AWS_REGION:-us-east-1}" --destroy "$@"
