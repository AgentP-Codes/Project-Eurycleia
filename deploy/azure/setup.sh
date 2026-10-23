#!/usr/bin/env bash
# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
#
# Sets up the Eurycleia live test in your Azure subscription. Run it in Azure Cloud Shell (Bash):
#
#   ./setup.sh all        everything below, in order (safe to run again)
#   ./setup.sh secrets    store or replace the app passwords and tokens in Key Vault (asks for each)
#   ./setup.sh infra      everything except the secrets (to finish or repair a setup)
#   ./setup.sh seed       load the made-up company into HubSpot and Stripe (test mode)
#   ./setup.sh feed N     send N made-up support emails into the test inbox (feed N again: a new round)
#   ./setup.sh enforce    switch Eurycleia from watch mode (log only) to blocking
#   ./setup.sh pause      kill switch: stop handling email      ./setup.sh resume   start again
#   ./setup.sh key openai           store an API key for another model provider (openai, anthropic, openrouter)
#   ./setup.sh model openai MODEL   switch the agent's model (model azure gpt-5-mini switches back)
#   ./setup.sh budget 5             the agent's daily model budget in A$
#   ./setup.sh status     what's set up, and the last few runs
#   ./setup.sh remove     delete EVERYTHING in the resource group, including the AI model
#
# Settings come from settings.env next to this script (copy settings.example.env). Nothing secret goes in it:
# secrets are typed in when asked and go straight into Key Vault.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$HERE/settings.env" ] || { echo "Copy settings.example.env to settings.env and fill it in first."; exit 1; }
# shellcheck disable=SC1091
source "$HERE/settings.env"

: "${RESOURCE_GROUP:?}" "${LOCATION:?}" "${AI_RESOURCE:?}" "${MODEL_DEPLOYMENT:?}" "${TEST_INBOX:?}"
: "${SLACK_SUPPORT_CHANNEL:?}" "${SLACK_REPORT_CHANNEL:?}" "${IMAGE:?}"
BUDGET_AUD_PER_DAY="${BUDGET_AUD_PER_DAY:-2}"
SUFFIX="$(echo -n "$(az account show --query id -o tsv)$RESOURCE_GROUP" | sha256sum | cut -c1-6)"
VAULT="${VAULT:-kv-eurycleia-$SUFFIX}"
STORAGE="${STORAGE:-steurycleia$SUFFIX}"
ENVIRONMENT="eurycleia-lab"      # a workload-profiles environment: "express" ones have no jobs or storage mounts
IDENTITY="eurycleia-agent-id"
SHARE="live-data"

say() { printf '\n== %s\n' "$*"; }

providers() {
  say "Making sure Azure Container Apps is available"
  az extension add --name containerapp --upgrade --only-show-errors >/dev/null
  for p in Microsoft.App Microsoft.OperationalInsights Microsoft.KeyVault Microsoft.Storage; do
    az provider register --namespace "$p" --wait >/dev/null
  done
}

vault() {
  say "Key Vault $VAULT (holds the app passwords and tokens)"
  if ! az keyvault show -n "$VAULT" -g "$RESOURCE_GROUP" >/dev/null 2>&1; then
    az keyvault create -n "$VAULT" -g "$RESOURCE_GROUP" -l "$LOCATION" --enable-rbac-authorization true \
      --retention-days 7 -o none
  fi
  local me vault_id
  me="$(az ad signed-in-user show --query id -o tsv)"
  vault_id="$(az keyvault show -n "$VAULT" -g "$RESOURCE_GROUP" --query id -o tsv)"
  az role assignment create --assignee-object-id "$me" --assignee-principal-type User \
    --role "Key Vault Secrets Officer" --scope "$vault_id" -o none 2>/dev/null || true
}

identity() {
  say "The agent's own Azure identity: it may read the vault's secrets and use the AI model, nothing more"
  az identity show -n "$IDENTITY" -g "$RESOURCE_GROUP" >/dev/null 2>&1 || \
    az identity create -n "$IDENTITY" -g "$RESOURCE_GROUP" -l "$LOCATION" -o none
  local principal vault_id ai_id
  principal="$(az identity show -n "$IDENTITY" -g "$RESOURCE_GROUP" --query principalId -o tsv)"
  vault_id="$(az keyvault show -n "$VAULT" -g "$RESOURCE_GROUP" --query id -o tsv)"
  ai_id="$(az cognitiveservices account show -n "$AI_RESOURCE" -g "$RESOURCE_GROUP" --query id -o tsv)"
  az role assignment create --assignee-object-id "$principal" --assignee-principal-type ServicePrincipal \
    --role "Key Vault Secrets User" --scope "$vault_id" -o none 2>/dev/null || true
  az role assignment create --assignee-object-id "$principal" --assignee-principal-type ServicePrincipal \
    --role "Cognitive Services OpenAI User" --scope "$ai_id" -o none 2>/dev/null || true
}

put_secret() {   # name, question; empty answer keeps what's there
  local name="$1" question="$2" value
  read -r -s -p "$question (press Enter to skip): " value; echo
  if [ -n "$value" ]; then
    for _ in 1 2 3 4 5 6; do      # a new role assignment can take a minute to apply
      if az keyvault secret set --vault-name "$VAULT" --name "$name" --file <(printf '%s' "$value") \
           --encoding utf-8 -o none 2>/dev/null; then echo "   saved $name"; return; fi
      sleep 15
    done
    echo "   couldn't save $name yet (Key Vault permissions still applying); run ./setup.sh secrets again"
  fi
}

secrets() {
  say "Secrets: typed here, stored only in Key Vault (nothing appears on screen)"
  put_secret gmail-app-password "Gmail app password for $TEST_INBOX (optional: Enter for no-email mode)"
  put_secret hubspot-token "HubSpot service key"
  put_secret stripe-test-key "Stripe secret key (must start with sk_test_)"
  put_secret slack-bot-token "Slack bot token (xoxb-...)"
  if [ -n "${IMAGE_TOKEN_USER:-}" ]; then
    put_secret image-pull-token "GitHub token with read:packages only (lets Azure download the private image)"
  fi
  if ! az keyvault secret show --vault-name "$VAULT" --name feeder-secret >/dev/null 2>&1; then
    az keyvault secret set --vault-name "$VAULT" --name feeder-secret \
      --file <(openssl rand -hex 32) --encoding utf-8 -o none && echo "   made feeder-secret"
  fi
}

storage() {
  say "Storage $STORAGE (results, audit log, reports)"
  az storage account show -n "$STORAGE" -g "$RESOURCE_GROUP" >/dev/null 2>&1 || \
    az storage account create -n "$STORAGE" -g "$RESOURCE_GROUP" -l "$LOCATION" --sku Standard_LRS \
      --kind StorageV2 --min-tls-version TLS1_2 --allow-blob-public-access false -o none
  local key
  key="$(az storage account keys list -n "$STORAGE" -g "$RESOURCE_GROUP" --query '[0].value' -o tsv)"
  az storage share-rm create --storage-account "$STORAGE" -g "$RESOURCE_GROUP" -n "$SHARE" --quota 1 -o none
  say "Container Apps environment $ENVIRONMENT"
  az containerapp env show -n "$ENVIRONMENT" -g "$RESOURCE_GROUP" >/dev/null 2>&1 || \
    az containerapp env create -n "$ENVIRONMENT" -g "$RESOURCE_GROUP" -l "$LOCATION" \
      --environment-mode WorkloadProfiles -o none
  for old in eurycleia-env eurycleia-jobs; do          # express environments from earlier tries: unused
    if az containerapp env show -n "$old" -g "$RESOURCE_GROUP" >/dev/null 2>&1; then
      echo "   removing the unused environment $old"
      az containerapp env delete -n "$old" -g "$RESOURCE_GROUP" --yes --no-wait -o none || true
    fi
  done
  az containerapp env storage set -n "$ENVIRONMENT" -g "$RESOURCE_GROUP" --storage-name livedata \
    --azure-file-account-name "$STORAGE" --azure-file-account-key "$key" --azure-file-share-name "$SHARE" \
    --access-mode ReadWrite -o none
}

job_yaml() {   # name, trigger (Schedule|Manual), cron, command (JSON list), args (JSON list)
  local env_id endpoint id_res client_id registry=""
  env_id="$(az containerapp env show -n "$ENVIRONMENT" -g "$RESOURCE_GROUP" --query id -o tsv)"
  endpoint="https://$AI_RESOURCE.openai.azure.com"
  id_res="$(az identity show -n "$IDENTITY" -g "$RESOURCE_GROUP" --query id -o tsv)"
  client_id="$(az identity show -n "$IDENTITY" -g "$RESOURCE_GROUP" --query clientId -o tsv)"
  if [ -n "${IMAGE_TOKEN_USER:-}" ]; then      # a private image: Azure signs in to the registry with the token
    registry="    secrets:
      - {name: image-pull-token, keyVaultUrl: \"https://$VAULT.vault.azure.net/secrets/image-pull-token\", identity: \"$id_res\"}
    registries:
      - {server: \"${IMAGE%%/*}\", username: \"$IMAGE_TOKEN_USER\", passwordSecretRef: image-pull-token}"
  fi
  cat <<YAML
location: $LOCATION
identity:
  type: UserAssigned
  userAssignedIdentities:
    "$id_res": {}
properties:
  environmentId: $env_id
  workloadProfileName: Consumption
  configuration:
    triggerType: $2
    replicaTimeout: 1500
    replicaRetryLimit: 0
$registry
$( [ "$2" = Schedule ] && printf '    scheduleTriggerConfig:\n      cronExpression: "%s"\n      parallelism: 1\n      replicaCompletionCount: 1\n' "$3" \
   || printf '    manualTriggerConfig:\n      parallelism: 1\n      replicaCompletionCount: 1\n' )
  template:
    containers:
      - name: agent
        image: $IMAGE
        command: $4
        args: $5
        resources: {cpu: 0.25, memory: 0.5Gi}
        env:
          - {name: TEST_INBOX, value: "$TEST_INBOX"}
          - {name: SLACK_SUPPORT_CHANNEL, value: "$SLACK_SUPPORT_CHANNEL"}
          - {name: SLACK_REPORT_CHANNEL, value: "$SLACK_REPORT_CHANNEL"}
          - {name: EURYCLEIA_KEY_VAULT, value: "https://$VAULT.vault.azure.net"}
          - {name: EURYCLEIA_PROVIDER, value: azure}
          - {name: AZURE_OPENAI_ENDPOINT, value: "$endpoint"}
          - {name: EURYCLEIA_MODEL, value: "$MODEL_DEPLOYMENT"}
          - {name: EURYCLEIA_BUDGET_AUD, value: "$BUDGET_AUD_PER_DAY"}
          - {name: EURYCLEIA_MODE, value: "${EURYCLEIA_MODE:-watch}"}
          - {name: EURYCLEIA_PAUSED, value: "${EURYCLEIA_PAUSED:-1}"}
          - {name: EURYCLEIA_DATA, value: /data}
          - {name: AZURE_CLIENT_ID, value: "$client_id"}
        volumeMounts:
          - {volumeName: data, mountPath: /data}
    volumes:
      - {name: data, storageType: AzureFile, storageName: livedata}
YAML
}

make_job() {   # name, trigger, cron, command, args
  local f; f="$(mktemp)"
  job_yaml "$@" > "$f"
  if az containerapp job show -n "$1" -g "$RESOURCE_GROUP" >/dev/null 2>&1; then
    az containerapp job update -n "$1" -g "$RESOURCE_GROUP" --yaml "$f" -o none
  else
    az containerapp job create -n "$1" -g "$RESOURCE_GROUP" --yaml "$f" -o none
  fi
  rm -f "$f"
}

jobs() {
  say "Jobs: the agent every 5 minutes, the daily report, and on-demand seed and feed"
  make_job eurycleia-agent Schedule "*/5 * * * *" '["python", "deploy/live/live.py"]' '["once"]'
  make_job eurycleia-report Schedule "55 21 * * *" '["python", "deploy/live/live.py"]' '["post-report"]'
  make_job eurycleia-seed Manual "" '["python", "deploy/live/seed.py"]' '[]'
  make_job eurycleia-feed Manual "" '["python", "deploy/live/feeder.py"]' '[]'
}

set_env() {   # NAME value: on the scheduled agent job
  az containerapp job update -n eurycleia-agent -g "$RESOURCE_GROUP" --set-env-vars "$1=$2" -o none
}

status() {
  say "Status"
  az containerapp job list -g "$RESOURCE_GROUP" --query "[].{job:name, image:properties.template.containers[0].image}" -o table
  say "Last runs of the agent"
  az containerapp job execution list -n eurycleia-agent -g "$RESOURCE_GROUP" \
    --query "[0:6].{started:properties.startTime, status:properties.status}" -o table 2>/dev/null || true
  echo; echo "Logs: Azure portal -> Container Apps jobs -> eurycleia-agent -> Execution history -> Console logs"
}

case "${1:-}" in
  all) providers; vault; identity; secrets; storage
       say "Waiting a minute for the new permissions to apply"; sleep 60
       jobs
       say "Done. The agent starts PAUSED. Next: ./setup.sh seed, then ./setup.sh resume, then ./setup.sh feed 5"
       echo "Mode: ${EURYCLEIA_MODE:-watch} (log only). Switch to blocking later with ./setup.sh enforce" ;;
  infra) providers; vault; identity; storage
         say "Waiting a minute for permissions to apply"; sleep 60
         jobs; say "Done. The agent starts PAUSED. Next: ./setup.sh seed" ;;
  secrets) vault; secrets ;;
  seed) az containerapp job start -n eurycleia-seed -g "$RESOURCE_GROUP" -o none
        echo "Seeding started; it takes a minute or two. Check: ./setup.sh status, or the seed job's logs." ;;
  feed) n="${2:-5}"; [[ "$n" =~ ^[0-9]+$ ]] || { echo "usage: ./setup.sh feed N [again]"; exit 1; }
        again=0; [ "${3:-}" = "again" ] && again=1     # again: a new round, starting from the first email
        az containerapp job update -n eurycleia-feed -g "$RESOURCE_GROUP" \
          --set-env-vars "FEED_COUNT=$n" "FEED_AGAIN=$again" -o none
        az containerapp job start -n eurycleia-feed -g "$RESOURCE_GROUP" -o none
        echo "Sending $n made-up emails$([ $again = 1 ] && echo ' (a new round)'). The agent picks them up within 5 minutes." ;;
  enforce) set_env EURYCLEIA_MODE enforce; echo "Eurycleia now blocks (enforce mode)." ;;
  watch)   set_env EURYCLEIA_MODE watch; echo "Eurycleia now only logs (watch mode)." ;;
  pause)   set_env EURYCLEIA_PAUSED 1; echo "Paused: no email is handled until ./setup.sh resume." ;;
  resume)  set_env EURYCLEIA_PAUSED 0; echo "Resumed." ;;
  key)     case "${2:-}" in openai|anthropic|openrouter|gemini) ;;
             *) echo "usage: ./setup.sh key openai|anthropic|openrouter|gemini"; exit 1 ;; esac
           vault; put_secret "$2-api-key" "$2 API key" ;;
  model)   prov="${2:-}"; mdl="${3:-}"
           case "$prov" in azure|openai|anthropic|openrouter|gemini) ;;
             *) echo "usage: ./setup.sh model azure|openai|anthropic|openrouter|gemini MODEL [PRICE_IN PRICE_OUT]"
                exit 1 ;; esac
           [ -n "$mdl" ] || { echo "say which model, e.g. ./setup.sh model openai gpt-5-mini"; exit 1; }
           vars=("EURYCLEIA_PROVIDER=$prov" "EURYCLEIA_MODEL=$mdl")
           if [ -n "${4:-}" ] && [ -n "${5:-}" ]; then     # US$ per million tokens, for a model not in pricing.py
             vars+=("EURYCLEIA_PRICE_IN=$4" "EURYCLEIA_PRICE_OUT=$5")
           else
             az containerapp job update -n eurycleia-agent -g "$RESOURCE_GROUP" \
               --remove-env-vars EURYCLEIA_PRICE_IN EURYCLEIA_PRICE_OUT -o none 2>/dev/null || true
           fi
           az containerapp job update -n eurycleia-agent -g "$RESOURCE_GROUP" --set-env-vars "${vars[@]}" -o none
           echo "The agent now uses $prov / $mdl from its next run." ;;
  budget)  [[ "${2:-}" =~ ^[0-9]+([.][0-9]+)?$ ]] || { echo "usage: ./setup.sh budget AUD_PER_DAY"; exit 1; }
           set_env EURYCLEIA_BUDGET_AUD "$2"; echo "Daily model budget: A\$$2." ;;
  status)  status ;;
  remove)
    read -r -p "Delete resource group $RESOURCE_GROUP and EVERYTHING in it, including the AI model? Type its name: " ok
    [ "$ok" = "$RESOURCE_GROUP" ] && az group delete -n "$RESOURCE_GROUP" --yes --no-wait && echo "Deleting." ;;
  *) sed -n '5,18p' "$0" ;;
esac
