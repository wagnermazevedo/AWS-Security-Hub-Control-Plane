# Controles

| Controle | Severidade | Avaliação no Security Hub | Laboratório | Remediação | Risco da remediação |
|---|---|---|---|---|---|
| S3.1 | MEDIUM | Periódica | `99` desliga o BPA da conta | `s3control:PutPublicAccessBlock` | Baixo; buckets públicos legítimos precisam de exceção antes |
| S3.8 | HIGH | Por mudança | Bucket do stack com BPA desligado | `s3:PutPublicAccessBlock` | Baixo; site estático público precisa da tag de exceção |
| EC2.2 | HIGH | Por mudança | SSH aberto no SG default da VPC do lab | Revoga todas as regras do SG `default` | Médio; confirme no plano que nenhum recurso usa o SG default |
| EC2.7 | MEDIUM | Periódica | `99` desliga a criptografia por padrão | `ec2:EnableEbsEncryptionByDefault` | Baixo; vale só para volumes novos |
| IAM.4 | CRITICAL | Periódica | Não simulado (nunca se cria chave de root) | Manual: finding `NOTIFIED` | Remover chave de root exige login de root com MFA |

Runbook do IAM.4: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user_manage_delete-key.html
