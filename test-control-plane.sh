#!/bin/bash

# ===================================================
# Configurações Globais
# ===================================================
AWS_REGION="us-east-1"
BASE_DIR="$HOME"
DEFAULT_REPO="Security-Control-Plane"

get_repo_description() {
    local repo_name="$1"
    case "$repo_name" in
        "Security-Control-Plane")
            echo "Plano de controle central para agregação, normatização e remediação geral de findings do Security Hub." ;;
        "AWS-Governance-as-Control-Plane")
            echo "Governança declarativa de postura, guardrails organizacionais e compliance contínuo." ;;
        "IAM-Identity-as-Control-Plane")
            echo "Controle de acesso, privilégios excessivos, gestão de credenciais e postura de identidades IAM." ;;
        "AWS-Network-Traffic-as-Control-Plane")
            echo "Inspeção e remediação de exposição de rede, Security Groups, VPCs e rotas de tráfego." ;;
        "Credential-Exposure-Control-Plane")
            echo "Detecção e resposta rápida para vazamento de chaves de acesso e credenciais expostas." ;;
        "PaaS-Managed-Services-Permissions-Control-Plane")
            echo "Segurança e permissões em serviços gerenciados (RDS, S3, DynamoDB, EKS, etc.)." ;;
        "Software-Defined-Perimeter-as-Control-Plane")
            echo "Gestão de perímetro definido por software, acesso zero-trust e regras de entrada/saída." ;;
        "AWS-Security-Scripts")
            echo "Coleção de utilitários e automações auxiliares para auditoria de segurança AWS." ;;
        *)
            echo "Módulo dinâmico de segurança e controle de postura em nuvem." ;;
    esac
}

anonimize_file() {
    local target_file="$1"
    if [ -f "$target_file" ]; then
        echo "   -> Anonimizando dados sensíveis em: $target_file"
        sed -i -E 's/[0-9]{12}/123456789012/g' "$target_file"
        sed -i -E 's/arn:aws:([a-zA-Cal-z0-9_-]+):([a-z0-9_-]+):123456789012:([^ \"]+)/arn:aws:\1:\2:123456789012:resource-masked/g' "$target_file"
        sed -i -E 's/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/user@masked-domain.local/g' "$target_file"
    fi
}

find_stage_script() {
    local repo_dir="$1"
    local stage="$2"
    local target_script=""
    
    target_script=$(ls -1 "$repo_dir"/scripts/${stage}_*.py 2>/dev/null | head -n 1)

    if [ -z "$target_script" ]; then
        case "$stage" in
            "00") target_script=$(ls -1 "$repo_dir"/scripts/*scan*.py 2>/dev/null | head -n 1) ;;
            "01") target_script=$(ls -1 "$repo_dir"/scripts/*plan*.py 2>/dev/null | head -n 1) ;;
            "02") target_script=$(ls -1 "$repo_dir"/scripts/*remediat*.py 2>/dev/null | head -n 1) ;;
        esac
    fi

    if [ -z "$target_script" ]; then
        target_script=$(ls -1 "$repo_dir"/${stage}_*.py 2>/dev/null | head -n 1)
    fi

    echo "$target_script"
}

find_rules_file() {
    local repo_dir="$1"
    local rules_file=""
    
    for possible_path in \
        "$repo_dir/config/remediate_map.yaml" \
        "$repo_dir/config/governance_rules.yaml" \
        "$repo_dir/config/rules.yaml" \
        "$repo_dir/scripts/remediate_map.yaml" \
        "$repo_dir/remediate_map.yaml" \
        "$repo_dir/config/"*.yaml \
        "$repo_dir/"*.yaml; do
        
        if [ -f "$possible_path" ] && [[ "$possible_path" != *"remediation_plan"* ]]; then
            rules_file="$possible_path"
            break
        fi
    done

    echo "$rules_file"
}

validate_repo_integrity() {
    local repo_dir="$1"
    local scan_s=$(find_stage_script "$repo_dir" "00")
    local plan_s=$(find_stage_script "$repo_dir" "01")
    local reme_s=$(find_stage_script "$repo_dir" "02")

    if [ -n "$scan_s" ] && [ -n "$plan_s" ] && [ -n "$reme_s" ]; then
        echo "INTEGRO"
    else
        local missing=""
        [ -z "$scan_s" ] && missing+="[SCAN (00)] "
        [ -z "$plan_s" ] && missing+="[PLAN (01)] "
        [ -z "$reme_s" ] && missing+="[REMEDIATE (02)] "
        echo "INCOMPLETO: Faltando $missing"
    fi
}

get_all_repos() {
    local found_repos=()
    for dir in "$BASE_DIR"/*/; do
        if [ -d "$dir" ]; then
            local folder_name=$(basename "$dir")
            if [[ "$folder_name" == .* ]]; then continue; fi
            if [ -d "$dir/.git" ] || [ -d "$dir/scripts" ]; then
                found_repos+=("${dir%/}")
            fi
        fi
    done
    echo "${found_repos[@]}"
}

# ===================================================
# Execuções Individuais de Estágios
# ===================================================

exec_scan() {
    local repo_dir="$1"
    local scan_script=$(find_stage_script "$repo_dir" "00")
    echo -e "\n[1/3] Executando SCAN usando: $(basename "$scan_script")..."
    
    PYTHONPATH="$repo_dir" python3 "$scan_script" --region "$AWS_REGION" --output-dir "$BASE_DIR/outputs"
    local ret_code=$?

    if [ $ret_code -eq 0 ]; then
        local input_yaml=$(ls -1td "$BASE_DIR/outputs"/202*/*.yaml "$repo_dir"/outputs/202*/*.yaml ./202*/*.yaml 2>/dev/null | head -n 1)
        if [ -n "$input_yaml" ]; then
            anonimize_file "$input_yaml"
            echo "-> Artefato de entrada preparado e mascarado: $input_yaml"
        fi
    else
        echo "❌ Erro na execução do Scan."
        exit 1
    fi
}

exec_plan() {
    local repo_dir="$1"
    local plan_script=$(find_stage_script "$repo_dir" "01")
    local rules_file=$(find_rules_file "$repo_dir")
    local plan_output="$BASE_DIR/remediation_plan.yaml"
    local input_yaml=$(ls -1td "$BASE_DIR/outputs"/202*/*.yaml "$repo_dir"/outputs/202*/*.yaml ./202*/*.yaml 2>/dev/null | head -n 1)

    if [ -z "$input_yaml" ]; then
        echo "❌ Erro: Nenhum arquivo YAML de scan anterior foi encontrado. Execute 'scan' primeiro."
        exit 1
    fi

    echo -e "\n[2/3] Executando PLAN usando: $(basename "$plan_script")..."
    if [ -n "$rules_file" ]; then
        PYTHONPATH="$repo_dir" python3 "$plan_script" --input-yaml "$input_yaml" --rules "$rules_file" --output-yaml "$plan_output"
    else
        PYTHONPATH="$repo_dir" python3 "$plan_script" --input-yaml "$input_yaml" --output-yaml "$plan_output"
    fi

    if [ ! -f "$plan_output" ]; then
        echo "❌ Erro: Falha ao gerar o plano de ação $plan_output"
        exit 1
    fi

    anonimize_file "$plan_output"
    echo "-> Plano gerado e mascarado: $plan_output"
}

exec_remediate() {
    local repo_dir="$1"
    local mode="$2"
    local remediate_script=$(find_stage_script "$repo_dir" "02")
    local plan_output="$BASE_DIR/remediation_plan.yaml"

    if [ ! -f "$plan_output" ]; then
        echo "❌ Erro: O arquivo '$plan_output' não existe. Execute 'plan' primeiro."
        exit 1
    fi

    echo -e "\n[3/3] Executando REMEDIATE em modo [$mode] usando: $(basename "$remediate_script")..."
    PYTHONPATH="$repo_dir" python3 "$remediate_script" --region "$AWS_REGION" --yaml "$plan_output" --mode "$mode"
}

# ===================================================
# Comandos Globais
# ===================================================

run_list_repos() {
    echo "===================================================="
    echo " AWS Security Control Plane: REPOSITÓRIOS DISPONÍVEIS "
    echo "===================================================="
    local repos=($(get_all_repos))
    if [ ${#repos[@]} -eq 0 ]; then
        echo "❌ Erro: Nenhum repositório de segurança encontrado em $BASE_DIR"
        exit 1
    fi
    echo -e "Total de módulos encontrados: ${#repos[@]}\n"
    for repo_path in "${repos[@]}"; do
        local repo_name=$(basename "$repo_path")
        local description=$(get_repo_description "$repo_name")
        local status=$(validate_repo_integrity "$repo_path")
        
        echo "📌 Repositório: $repo_name"
        echo "   📁 Diretório : $repo_path"
        if [[ "$status" == "INTEGRO" ]]; then
            echo "   ✅ Status    : ÍNTEGRO (Scan, Plan e Remediate presentes)"
        else
            echo "   ⚠️ Status    : $status"
        fi
        echo "   💡 Descrição : $description"
        echo "----------------------------------------------------"
    done
    exit 0
}

run_scan_all() {
    echo "===================================================="
    echo " AWS Security Control Plane: MODO SCAN-ALL "
    echo "===================================================="
    local repos=($(get_all_repos))
    local total_scans=0
    local success_scans=0

    for repo_path in "${repos[@]}"; do
        local repo_name=$(basename "$repo_path")
        local scan_script=$(find_stage_script "$repo_path" "00")
        local status=$(validate_repo_integrity "$repo_path")

        total_scans=$((total_scans + 1))
        echo -e "\n[$total_scans/${#repos[@]}] Processando: $repo_name"

        if [[ "$status" != "INTEGRO" ]]; then
            echo "   ⚠️ Pulando $repo_name: Repositório não está íntegro ($status)"
            continue
        fi

        echo "   -> Executando SCAN usando: $(basename "$scan_script")..."
        PYTHONPATH="$repo_path" python3 "$scan_script" --region "$AWS_REGION" --output-dir "$BASE_DIR/outputs"
        
        if [ $? -eq 0 ]; then
            local latest_yaml=$(ls -1td "$BASE_DIR/outputs"/202*/*.yaml "$repo_path"/outputs/202*/*.yaml ./202*/*.yaml 2>/dev/null | head -n 1)
            if [ -n "$latest_yaml" ]; then
                anonimize_file "$latest_yaml"
                echo "   ✅ Scan concluído e mascarado: $latest_yaml"
                success_scans=$((success_scans + 1))
            fi
        else
            echo "   ❌ Falha na execução do Scan em $repo_name"
        fi
    done
    
    echo -e "\n===================================================="
    echo " Execução do SCAN-ALL finalizada! "
    echo " Sucesso: $success_scans / $total_scans repositórios íntegros "
    echo "===================================================="
    exit 0
}

# ===================================================
# Roteamento Principal
# ===================================================

case "$1" in
    "list-repos") run_list_repos ;;
    "scan-all") run_scan_all ;;
esac

SELECTED_REPO="${1:-$DEFAULT_REPO}"
ACTION="${2:-dry-run}"

REPO_DIR="$BASE_DIR/$SELECTED_REPO"

if [ ! -d "$REPO_DIR" ]; then
    echo "❌ Erro: O repositório '$REPO_DIR' não foi encontrado em $BASE_DIR."
    echo ""
    echo "Uso da CLI:"
    echo "  $0 list-repos"
    echo "  $0 scan-all"
    echo "  $0 [NOME_REPO] [scan|plan|remediate-dry-run|remediate-apply|dry-run|apply]"
    exit 1
fi

INTEGRITY_STATUS=$(validate_repo_integrity "$REPO_DIR")
if [[ "$INTEGRITY_STATUS" != "INTEGRO" ]]; then
    echo "❌ Erro: O repositório '$SELECTED_REPO' não atende ao critério de integridade!"
    echo "   Detalhes: $INTEGRITY_STATUS"
    exit 1
fi

REPO_DESC=$(get_repo_description "$SELECTED_REPO")

echo "===================================================="
echo " AWS Security Control Plane Automation Suite "
echo " Repositório Alvo: $SELECTED_REPO "
echo " Diretório Path  : $REPO_DIR "
echo " Descrição       : $REPO_DESC "
echo " Ação Solicitada : $ACTION "
echo "===================================================="

cd "$REPO_DIR" || exit 1

case "$ACTION" in
    "scan")
        exec_scan "$REPO_DIR"
        ;;
    "plan")
        exec_plan "$REPO_DIR"
        ;;
    "remediate-dry-run")
        exec_remediate "$REPO_DIR" "dry-run"
        ;;
    "remediate-apply")
        exec_remediate "$REPO_DIR" "apply"
        ;;
    "dry-run")
        exec_scan "$REPO_DIR"
        exec_plan "$REPO_DIR"
        exec_remediate "$REPO_DIR" "dry-run"
        ;;
    "apply")
        exec_scan "$REPO_DIR"
        exec_plan "$REPO_DIR"
        exec_remediate "$REPO_DIR" "apply"
        ;;
    *)
        echo "❌ Erro: Ação '$ACTION' não reconhecida."
        echo ""
        echo "Ações válidas:"
        echo "  - scan               : Executa apenas a auditoria [00]"
        echo "  - plan               : Executa apenas a geração do plano [01]"
        echo "  - remediate-dry-run  : Executa apenas a simulação de remediação [02]"
        echo "  - remediate-apply    : Executa apenas a aplicação real da remediação [02]"
        echo "  - dry-run            : Executa o fluxo completo (Scan -> Plan -> Remediate Dry-Run)"
        echo "  - apply              : Executa o fluxo completo (Scan -> Plan -> Remediate Apply)"
        exit 1
        ;;
esac

echo -e "\n===================================================="
echo " Execução finalizada com sucesso! "
echo " Repositório: $SELECTED_REPO "
echo " Ação: $ACTION "
echo "===================================================="
