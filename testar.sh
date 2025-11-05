#!/bin/bash
set -u
# Habilita nullglob para que padrões vazios não se expandam para o literal "*.rpm"
shopt -s nullglob

# --- Variáveis ---
# 10 pacotes
REPO_PATH="/home/stuepp/opensuse_rpms/opensuse.c3sl.ufpr.br_distribution_leap_16.0_repo_non-oss_noarch_/distribution/leap/16.0/repo/non-oss/noarch/"

# 21 pacotes
# REPO_PATH="/home/stuepp/opensuse_rpms/opensuse.c3sl.ufpr.br_distribution_leap_16.0_repo_non-oss_x86_64_/distribution/leap/16.0/repo/non-oss/x86_64/"

# 17703 pacotes
# REPO_PATH="/home/stuepp/opensuse_rpms/opensuse.c3sl.ufpr.br_distribution_leap_16.0_repo_oss_noarch_/distribution/leap/16.0/repo/oss/noarch/"

# 18545 pacotes
# REPO_PATH="/home/stuepp/opensuse_rpms/opensuse.c3sl.ufpr.br_distribution_leap_16.0_repo_oss_x86_64_/distribution/leap/16.0/repo/oss/x86_64/"

#REPO_PATH="/root/TCC/repo1/"
RPM_KEYS_DIR="/etc/pki/rpm-gpg"

declare -a list_key_ids_used
declare -A ALGO_MAP=(
    [1]="RSA"
    [17]="DSA"
    [19]="ECDSA"
    [22]="EDDSA"
)
declare -a package_versions=()
declare -a alg_hash_e_tamanhos_usados=()
declare -a non_signed_packs=()
declare -a pacotes_not_ok=()

SIG_OK=0
SIG_NOK=0

# --- Funções ---

package_hashAlg_hashSize(){
    local sig_line="$1"
    local key_id
    key_id=$(echo "$sig_line" | awk '{print $NF}' || true)
    key_id="${key_id,,}"

    local alg_hash_e_tamanho
    alg_hash_e_tamanho=$(echo "$sig_line" | grep -oE 'SHA[0-9]+' || true)

    if [[ -z "$key_id" ]]; then
        return
    fi

    for tuple in "${alg_hash_e_tamanhos_usados[@]}"; do
        IFS=',' read -r existing_key existing_hash <<< "$tuple"
        if [[ "$existing_key" == "$key_id" && "$existing_hash" == "$alg_hash_e_tamanho" ]]; then
            return
        fi
    done

    alg_hash_e_tamanhos_usados+=("$key_id,$alg_hash_e_tamanho")
}

verificando_assinatura() {
    local package="$1"
    local signature_status
    signature_status=$(rpm -K "$package" 2>/dev/null || true)

    if echo "$signature_status" | grep -qE "NOT OK"; then
        ((SIG_NOK++))
        pacotes_not_ok+=("$package")
    else
        ((SIG_OK++))
    fi
}

add_key_to_keyused_list() {
    local key_id="$1"
    key_id="${key_id,,}"
    for k in "${list_key_ids_used[@]}"; do
        if [[ "$k" == "$key_id" ]]; then
            return
        fi
    done
    list_key_ids_used+=("$key_id")
}

chave_usada_para_assinar_pacote(){
    local TOTAL_DE_PACOTES_ASSINADOS=0
    local nao_assinados=0

    if [[ ! -d "$REPO_PATH" ]]; then
        echo -e "\t[ERRO] REPO_PATH não existe: $REPO_PATH"
        return
    fi

    for pacote in "$REPO_PATH"/*.rpm; do
        [[ ! -f "$pacote" ]] && continue

        local sig_line
        sig_line=$(rpm -qp --qf '%{SIGPGP:pgpsig}\n' "$pacote" 2>/dev/null || true)
        if [[ -z "$sig_line" ]]; then
            sig_line=$(rpm -qp --qf '%{SIGMD5:pgpsig}\n' "$pacote" 2>/dev/null || true)
        fi

        if [[ -z "$sig_line" || "$sig_line" =~ \(none\) ]]; then
            non_signed_packs+=("$pacote")
            ((nao_assinados++))
            continue
        fi

        ((TOTAL_DE_PACOTES_ASSINADOS++))
        package_hashAlg_hashSize "$sig_line"
        verificando_assinatura "$pacote"

        local key_id
        key_id=$(echo "$sig_line" | awk '{print $NF}' || true)
        key_id="${key_id,,}"
        add_key_to_keyused_list "$key_id"
    done

    echo -e "\tChaves usadas para assinar os pacotes:"
    for k in "${list_key_ids_used[@]}"; do
        local short_key_id="${k: -8}"
        local key_used
        key_used=$(rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SUMMARY}\n' 2>/dev/null | grep -F "$short_key_id" || true)

        if [[ -n "$key_used" ]]; then
            echo -e "\t\tConheço essa chave:"
            echo -e "\t\t$key_used"
        else
            echo -e "\t\tDesconheço essa chave:"
            echo -e "\t\t$k"
        fi
    done

    echo
    echo -e "\tTotal de chaves com assinatura OK: $SIG_OK"
    echo -e "\tTotal de chaves com assinatura NOT OK: $SIG_NOK"

    if (( ${#pacotes_not_ok[@]} )); then
        echo -e "\tPacotes NOT OK:"
        for p in "${pacotes_not_ok[@]}"; do
            echo -e "\t\t$p"
        done
    fi

    local total_de_pacotes
    total_de_pacotes=$(compgen -G "$REPO_PATH/*.rpm" | wc -l)
    echo
    echo -e "\tTotal de pacotes: $total_de_pacotes"
    echo -e "\tTotal de pacotes assinados: $TOTAL_DE_PACOTES_ASSINADOS"
    echo -e "\tTotal de pacotes não assinados: $nao_assinados"
    echo

    if (( ${#non_signed_packs[@]} )); then
        echo -e "\tPacotes não assinados:"
        for p in "${non_signed_packs[@]}"; do
            echo -e "\t\t$p"
        done
    fi
}

quem_certificou(){
    local key="$1"
    local sigs
    sigs=$(gpg --show-keys --with-colons "$key" 2>/dev/null | grep '^sig' || true)

    if [[ -n "$sigs" ]]; then
        local i=1
        while IFS= read -r sig; do
            printf "\t\tAssinatura %d: %s\n" "$i" "$sig"
            ((i++))
        done <<<"$sigs"
    else
        echo -e "\t\tnenhuma assinatura encontrada"
    fi
}

coleta_info_da_chave(){
    local key="$1"
    local key_info
    key_info=$(gpg --show-keys --with-colons "$key" 2>/dev/null | awk -F: '$1 == "pub" {print $3 ":" $4 ":" $6 ":" $7; exit}')

    if [[ -z "$key_info" ]]; then
        echo -e "\t\t[AVISO] Não foi possível obter info da chave: $key"
        return
    fi

    local size_bits algo_id creation_ts expiration_ts
    IFS=':' read -r size_bits algo_id creation_ts expiration_ts <<< "$key_info"

    if ! [[ "$creation_ts" =~ ^[0-9]+$ ]]; then
        creation_ts=""
    fi
    if ! [[ "$expiration_ts" =~ ^[0-9]+$ ]]; then
        expiration_ts=""
    fi

    local creation_date="Desconhecida"
    local expiration_date="Não tem"
    local lifespan="Indefinido"

    if [[ -n "$creation_ts" ]]; then
        creation_date=$(date -d "@$creation_ts" '+%Y-%m-%d' 2>/dev/null || echo "Desconhecida")
    fi
    if [[ -n "$expiration_ts" && -n "$creation_ts" ]]; then
        expiration_date=$(date -d "@$expiration_ts" '+%Y-%m-%d' 2>/dev/null || echo "Desconhecida")
        lifespan=$(( (expiration_ts - creation_ts) / 86400 ))
    elif [[ -n "$expiration_ts" ]]; then
        expiration_date=$(date -d "@$expiration_ts" '+%Y-%m-%d' 2>/dev/null || echo "Desconhecida")
    fi

    local algo_name="Desconhecido"
    if [[ "$algo_id" =~ ^[0-9]+$ ]] && [[ -n "${ALGO_MAP[$algo_id]:-}" ]]; then
        algo_name="${ALGO_MAP[$algo_id]}"
    else
        algo_name="Desconhecido($algo_id)"
    fi

    echo -e "\t\tAlgoritimo utilizado: $algo_name -- Tamanho: ${size_bits:-Desconhecido} -- Data de criação: $creation_date -- Data de expiração: $expiration_date -- Tempo de vida: $lifespan"

    quem_certificou "$key"
}

algoritmos_criptograficos_usados_e_tamanhos_de_chave() {
    echo -e "\nConferindo algoritmos criptográficos usados e tamanhos de chave utilizados:\n"

    local os
    os=$(head -1 /etc/os-release 2>/dev/null | grep "Fedora" || true)
    if [[ -n "$os" ]]; then
        echo -e "\tEstamos no Fedora"
        echo -e "\tChave do dir /etc/pki/rpm-gpg"

        local fedora_in_use_key
        fedora_in_use_key=$(ls "$RPM_KEYS_DIR" 2>/dev/null | head -1 || true)
        if [[ -n "$fedora_in_use_key" ]]; then
            echo -e "\t\tChave sendo verificada: $fedora_in_use_key"
            coleta_info_da_chave "$RPM_KEYS_DIR/$fedora_in_use_key"
        else
            echo -e "\t\t[AVISO] Diretório $RPM_KEYS_DIR vazio ou inacessível."
        fi
    else
        echo -e "\tEstamos em uma OS diferente do Fedora (provavelmente openSUSE ou derivado)"
    fi

    echo
    echo -e "\tVerificando agora chaves utilizadas pelos pacotes"
    echo

    if (( ${#list_key_ids_used[@]} )); then
        IFS=$'\n' read -r -d '' -a list_key_ids_used < <(printf "%s\n" "${list_key_ids_used[@]}" | sort -u && printf '\0')
    fi

    for k in "${list_key_ids_used[@]}"; do
        [[ -z "$k" ]] && continue
        local short_key_id="${k: -8}"
        local key_used
        key_used=$(rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SUMMARY}\n' 2>/dev/null | grep -F "$short_key_id" || true)

        if [[ -n "$key_used" ]]; then
            echo -e "\t\tChave sendo verificada: $key_used"

            # Extração de data de ativação e expiração
            echo -e "\t\tExtraindo informações da chave..."

            # Captura o nome do pacote correto (exemplo: gpg-pubkey-29b700a4-62b07e22)
            pkg_name=$(echo "$key_used" | awk '{print $1}')

            # Extrai o bloco PGP da chave instalada via rpm
            key_block=$(rpm -qi "$pkg_name" 2>/dev/null | \
                sed -n '/-----BEGIN PGP PUBLIC KEY BLOCK-----/,/-----END PGP PUBLIC KEY BLOCK-----/p')

            if [[ -n "$key_block" ]]; then
                # Extrai datas (epoch) de criação e expiração usando gpg
                key_info=$(echo "$key_block" | \
                    gpg --with-colons --import-options show-only --import 2>/dev/null | \
                    awk -F: '$1 == "pub" {print $6 ":" $7; exit}')

                if [[ -n "$key_info" ]]; then
                    creation_ts=$(echo "$key_info" | cut -d':' -f1)
                    expiration_ts=$(echo "$key_info" | cut -d':' -f2)

                    creation_date=$(date -d "@$creation_ts" '+%Y-%m-%d' 2>/dev/null || echo "Desconhecida")
                    if [[ -n "$expiration_ts" && "$expiration_ts" -ne 0 ]]; then
                        expiration_date=$(date -d "@$expiration_ts" '+%Y-%m-%d' 2>/dev/null || echo "Desconhecida")
                    else
                        expiration_date="Não expira"
                    fi

                    echo -e "\t\tData de criação: $creation_date"
                    echo -e "\t\tData de expiração: $expiration_date"
                else
                    echo -e "\t\t[AVISO] Não foi possível obter as datas da chave."
                fi
            else
                echo -e "\t\t[AVISO] Bloco PGP não encontrado no pacote $pkg_name."
            fi

            echo -e "\t\tResumo do pacote associado:"
            rpm -qi "$key_used" 2>/dev/null | grep -E "Name|Version|Release|Summary" | sed 's/^/\t\t\t/' || true

        else
            echo -e "\t\tChave sendo verificada: $k"
            echo -e "\t\tNão se tem a chave localmente — será necessário baixá-la para análise completa."
        fi
    done

    echo
    echo -e "\tAlgoritmo de hash e tamanho utilizados"
    for pv in "${alg_hash_e_tamanhos_usados[@]}"; do
        IFS=',' read -r chave alg_info <<< "$pv"
        if [[ -n "$alg_info" ]]; then
            echo -e "\t\tChave: $chave; Algoritmo hash e tamanho: $alg_info"
        else
            echo -e "\t\t[AVISO] Nenhum dado de algoritmo/tamanho coletado para chave: $chave"
        fi
    done
}

verifica_RPM(){
    local batch_size=3
    local batch=()
    package_versions=()

    for pacote in "$REPO_PATH"/*.rpm; do
        [[ ! -f "$pacote" ]] && continue
        batch+=("$pacote")
        if (( ${#batch[@]} == batch_size )); then
            while IFS= read -r versao; do
                adicionar_versao "$versao"
            done < <("./$EXECUTABLE_NAME" "${batch[@]}" | awk -F': ' '{if ($2 ~ /^[0-9]+(\.[0-9]+)*$/) print $2}')
            batch=()
        fi
    done

    if (( ${#batch[@]} > 0 )); then
        while IFS= read -r versao; do
            adicionar_versao "$versao"
        done < <("./$EXECUTABLE_NAME" "${batch[@]}" | awk -F': ' '{if ($2 ~ /^[0-9]+(\.[0-9]+)*$/) print $2}')
    fi

    echo "Versões encontradas:"
    for ver in "${package_versions[@]}"; do
        echo "$ver"
    done
}

adicionar_versao(){
    local nova_versao="$1"
    local existe=0
    for v in "${package_versions[@]}"; do
        if [[ "$v" == "$nova_versao" ]]; then
            existe=1
            break
        fi
    done
    if (( ! existe )); then
        package_versions+=("$nova_versao")
    fi
}

# --- Main ---
echo
echo "Conferindo as chaves usadas para assinar pacotes:"

chave_usada_para_assinar_pacote

echo "-----------------------------------"
algoritmos_criptograficos_usados_e_tamanhos_de_chave

C_SOURCE_FILE="rpmver.c"
EXECUTABLE_NAME="rpmver"

if [[ -f "$C_SOURCE_FILE" ]]; then
    gcc "$C_SOURCE_FILE" -o "$EXECUTABLE_NAME" 2>/dev/null || true

    if [ $? -eq 0 ] && [[ -x "./$EXECUTABLE_NAME" ]]; then
        echo
        echo "Compilation of $C_SOURCE_FILE was successful. Executable name -> $EXECUTABLE_NAME"
        echo "-----------------------------------"
        echo "Verificando versão RPM dos pacotes:"
        verifica_RPM
    else
        echo
        echo "Não foi possivel compilar $C_SOURCE_FILE"
    fi
else
    echo -e "\t[AVISO] $C_SOURCE_FILE não encontrado, pulando etapa de verificação de versões."
fi
