#!/bin/bash
set -euo pipefail

# Diretório base para os downloads
BASE_DIR="opensuse_rpms"
mkdir -p "$BASE_DIR"

# Lista dos repositórios
repos=(
  "https://opensuse.c3sl.ufpr.br/distribution/leap/16.0/repo/non-oss/noarch/"
  "https://opensuse.c3sl.ufpr.br/distribution/leap/16.0/repo/non-oss/x86_64/"
)

baixar_repo() {
    local repo_url="$1"
    local repo_name
    repo_name=$(echo "$repo_url" | sed 's|https://||; s|/|_|g')

    local output_dir="$BASE_DIR/$repo_name"
    mkdir -p "$output_dir"

    echo "📦 Baixando arquivos .rpm de:"
    echo "   $repo_url"
    echo "   → Salvando em: $output_dir"
    echo

    wget --recursive --level=1 --no-parent --no-directories \
        --accept "*.rpm" \
        --no-check-certificate \
        --quiet --show-progress \
        --directory-prefix="$output_dir" \
        "$repo_url"

    echo
    echo "✅ Concluído: $repo_url"
    echo "---------------------------------------------"
    echo
}

for repo in "${repos[@]}"; do
    baixar_repo "$repo"
done

echo "🎉 Todos os pacotes .rpm foram baixados com sucesso!"
echo "📂 Local: $BASE_DIR"
