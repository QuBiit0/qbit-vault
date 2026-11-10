#!/usr/bin/env bash
# Runs inside the VHS container (see make.sh). Builds a throwaway demo vault
# with obviously fake values. The scripted prompt backend answers the prompts
# from files, so nothing here needs a person or a real secret.
set -euo pipefail

export HOME=/root/demo
export QBIT_VAULT_HOME=$HOME/vault
export XDG_RUNTIME_DIR=/dev/shm/demo-runtime   # tmpfs: lets `unlock` cache the key
export QBIT_VAULT_PROMPT=scripted
export QBIT_VAULT_SCRIPTED_PASSPHRASE_FILE=$HOME/.passphrase
export QBIT_VAULT_SCRIPTED_ANSWERS=$HOME/.answers
export QBIT_VAULT_SCRIPTED_TRANSCRIPT=$HOME/.transcript
export QBIT_VAULT_NO_REMOTE=1
export QBIT_VAULT_NO_UPDATE_CHECK=1

mkdir -p "$HOME/.claude" "$XDG_RUNTIME_DIR" "$HOME/work/acme-api/.git"
chmod 700 "$XDG_RUNTIME_DIR"
printf '%s\n' 'demo-passphrase-not-a-secret' >"$HOME/.passphrase"

answers() { printf '%s\n' "$@" >"$QBIT_VAULT_SCRIPTED_ANSWERS"; }
qv() { qbit-vault "$@" >/dev/null; }

answers
qv init --passphrase --agents claude-code

answers 'ghp_DEMO0000000000000000000000000000fake'
qv set GITHUB_TOKEN --global --description 'GitHub CLI and API access' --binaries gh,git
answers 'sk-demo-0000000000000000000000000000fake'
qv set OPENAI_API_KEY --global --description 'OpenAI API, used by the eval scripts'
answers 'postgres://demo:demo-pass-fake@db.example.test:5432/app'
qv set DATABASE_URL --global --description 'Staging database connection string'
answers 'sk_test_DEMO0000000000000000000000fake'
qv set STRIPE_SECRET_KEY --global --description 'Stripe test-mode secret key' --sensitive
answers 'acme-api-demo-token-0000000000fake'
(cd "$HOME/work/acme-api" && qv set ACME_API_TOKEN --project --description 'Token for the acme-api service')

# Two session grants, confirmed on the (scripted) prompt like a user would.
for name in GITHUB_TOKEN OPENAI_API_KEY; do
  answers y
  qv grant "$name" --global --scope session --session demo:vhs-1
done

qv unlock
: >"$QBIT_VAULT_SCRIPTED_ANSWERS"

# What the exec in cli.tape runs: a script that prints the injected token.
cat >"$HOME/work/acme-api/show-token.sh" <<'SH'
echo "calling api.openai.com with key $OPENAI_API_KEY"
SH
