#!/usr/bin/env bash
#
# verify-provenance.sh — Vérifie l'attestation SLSA d'une image SANS accès au registry.
#
# Le digest est censé provenir d'une source de confiance (ex. attestation TDX).
# Le script :
#   1. récupère le bundle d'attestation depuis l'API GitHub (par digest, pas via le registry)
#   2. vérifie la signature + l'identité du signataire depuis le bundle seul
#   3. confirme que le subject de l'attestation == le digest fourni (binding)
#   4. affiche le repo source et le commit
#
# Usage:
#   ./verify-provenance.sh <entrypoint-workflow-repo> <sign-action-repo> <sha256-digest>
#   ./verify-provenance.sh aghiles-ait/test-sigstore aghiles-ait/test-sigstore 0a50000f...969a
#
# Arguments :
#   <entrypoint-workflow-repo>  owner/name — repo dont l'événement a déclenché le run
#                               (où est stockée l'attestation, interrogé via l'API GitHub)
#   <sign-action-repo>          owner/name — repo du workflow qui SIGNE (le reusable
#                               workflow). Sert à contraindre l'identité du certificat.
#                               = entrypoint-workflow-repo si la signature n'est pas reusable.
#   <sha256-digest>             digest de l'image (formes "sha256:abc..." ou "abc...")
#
# Variables d'environnement optionnelles :
#   GITHUB_TOKEN  pour repo privé / éviter le rate-limit anonyme

set -euo pipefail

# Constantes (GitHub Actions keyless + SLSA v1)
ISSUER="https://token.actions.githubusercontent.com"
PREDICATE="slsaprovenance1"

# --- arguments -------------------------------------------------------------
if [ $# -ne 3 ]; then
  echo "Usage: $0 <entrypoint-workflow-repo> <sign-action-repo> <sha256-digest>" >&2
  echo "   ex: $0 aghiles-ait/test-sigstore aghiles-ait/test-sigstore 0a50000f...969a" >&2
  exit 2
fi

ENTRYPOINT_WORKFLOW_REPO="$1"   # repo qui détient l'attestation (appel API)
SIGN_ACTION_REPO="$2"           # repo du workflow signataire (identité du cert)

# Accepte aussi bien "sha256:abc..." que "abc..."
D="${3#sha256:}"

for var in ENTRYPOINT_WORKFLOW_REPO SIGN_ACTION_REPO; do
  if ! printf '%s' "${!var}" | grep -Eq '^[^/]+/[^/]+$'; then
    echo "❌ $var invalide : attendu 'owner/name', reçu : ${!var}" >&2
    exit 2
  fi
done

if ! printf '%s' "$D" | grep -Eq '^[a-f0-9]{64}$'; then
  echo "❌ Digest invalide : attendu 64 caractères hex (sha256), reçu : $3" >&2
  exit 2
fi

# --- dépendances -----------------------------------------------------------
for bin in curl jq cosign; do
  command -v "$bin" >/dev/null 2>&1 || { echo "❌ Outil manquant : $bin" >&2; exit 1; }
done

BUNDLE="$(mktemp -t bundle.XXXXXX.json)"
RESP="$(mktemp -t resp.XXXXXX.json)"
trap 'rm -f "$BUNDLE" "$RESP"' EXIT

# --- 1) récupérer le bundle depuis GitHub PAR DIGEST (zéro registry) -------
# On interroge l'API GitHub par digest : aucun appel au registry de l'image.
echo "→ Récupération du bundle depuis GitHub (repo: $ENTRYPOINT_WORKFLOW_REPO, digest: sha256:$D)"
AUTH=()
[ -n "${GITHUB_TOKEN:-}" ] && AUTH=(-H "Authorization: Bearer $GITHUB_TOKEN")
curl -sS "${AUTH[@]+"${AUTH[@]}"}" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/$ENTRYPOINT_WORKFLOW_REPO/attestations/sha256:$D" -o "$RESP"

jq '.attestations[0].bundle' "$RESP" > "$BUNDLE" 2>/dev/null || true
if [ ! -s "$BUNDLE" ] || [ "$(cat "$BUNDLE")" = "null" ]; then
  echo "❌ Aucune attestation trouvée pour sha256:$D dans $ENTRYPOINT_WORKFLOW_REPO" >&2
  jq -r '.message // empty' "$RESP" 2>/dev/null | sed 's/^/   GitHub: /' >&2 || true
  exit 1
fi

# --- 2) vérifier signature + identité depuis le bundle seul ----------------
# Le SAN du certificat = workflow signataire (le reusable workflow s'il y en a un),
# donc on contraint l'identité au repo du SIGNATAIRE, pas à celui de l'attestation.
echo "→ Vérification de la signature (cert Fulcio + Rekor, hors-ligne)"
cosign verify-blob-attestation \
  --new-bundle-format \
  --bundle "$BUNDLE" \
  --type "$PREDICATE" \
  --certificate-identity-regexp "^https://github.com/$SIGN_ACTION_REPO/\.github/workflows/" \
  --certificate-oidc-issuer "$ISSUER" \
  --check-claims=false >/dev/null

# --- 3) binding : le subject de l'attestation == le digest fourni ----------
echo "→ Vérification du binding (subject == digest fourni)"
SUBJECT="$(jq -r '.dsseEnvelope.payload | @base64d | fromjson | .subject[].digest.sha256' "$BUNDLE")"
if [ "$SUBJECT" != "$D" ]; then
  echo "❌ L'attestation parle d'une AUTRE image :" >&2
  echo "     attendu : $D" >&2
  echo "     trouvé  : $SUBJECT" >&2
  exit 1
fi

# --- 4) extraire la source --------------------------------------------------
PAYLOAD="$(jq -r '.dsseEnvelope.payload | @base64d' "$BUNDLE")"
URI="$(printf '%s' "$PAYLOAD"      | jq -r '.predicate.buildDefinition.resolvedDependencies[0].uri')"
COMMIT="$(printf '%s' "$PAYLOAD"   | jq -r '.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit')"
EVENT="$(printf '%s' "$PAYLOAD"    | jq -r '.predicate.buildDefinition.internalParameters.github.event_name')"
# Workflow DÉCLENCHEUR (entrée) : externalParameters.workflow (repository + path)
ENTRY_WF_REPO="$(printf '%s' "$PAYLOAD" | jq -r '.predicate.buildDefinition.externalParameters.workflow.repository')"
ENTRY_WF_PATH="$(printf '%s' "$PAYLOAD" | jq -r '.predicate.buildDefinition.externalParameters.workflow.path')"
# Workflow BUILDER/SIGNATAIRE (le reusable) : runDetails.builder.id ("https://…/<path>@<sha>")
BUILDER_ID="$(printf '%s' "$PAYLOAD" | jq -r '.predicate.runDetails.builder.id')"

# Lien cliquable vers l'arborescence du repo à ce commit :
#   git+https://github.com/<owner>/<repo>@refs/... -> https://github.com/<owner>/<repo>/tree/<sha>
REPO_URL="${URI#git+}"      # retire le préfixe "git+"
REPO_URL="${REPO_URL%@*}"   # retire le suffixe "@refs/..."
COMMIT_URL="${REPO_URL}/tree/${COMMIT}"

# Lien vers le workflow DÉCLENCHEUR, pinné au commit source (blob) :
WORKFLOW_URL="${ENTRY_WF_REPO}/blob/${COMMIT}/${ENTRY_WF_PATH}"

# Lien vers le workflow BUILDER (reusable). builder.id = "https://github.com/<owner>/<repo>/<path>@<sha>"
# -> URL "blob" pinnée au <sha> embarqué dans l'identifiant.
BUILDER_NOREF="${BUILDER_ID%@*}"                                       # sans @<sha>
BUILDER_REF="${BUILDER_ID##*@}"                                        # le <sha>
BUILDER_NOHOST="${BUILDER_NOREF#https://github.com/}"                  # owner/repo/.github/workflows/file.yml
BUILDER_OWNER_REPO="$(printf '%s' "$BUILDER_NOHOST" | cut -d/ -f1-2)"
BUILDER_PATH="$(printf '%s' "$BUILDER_NOHOST" | cut -d/ -f3-)"
BUILDER_URL="https://github.com/${BUILDER_OWNER_REPO}/blob/${BUILDER_REF}/${BUILDER_PATH}"

# Lien vers l'entrée Rekor (log de transparence) par hash de l'image
REKOR_URL="https://search.sigstore.dev/?hash=${D}"

# Lien vers l'attestation sur GitHub.
# NB : l'ID exact n'est pas exposé par l'API ; on le DÉDUIT du bundle_url (.../<id>.json...),
# format non documenté -> best-effort. Fallback : la page liste des attestations (toujours valide).
BUNDLE_URL="$(jq -r '.attestations[0].bundle_url // empty' "$RESP")"
ATT_ID="$(printf '%s' "$BUNDLE_URL" | sed -nE 's#.*/([0-9]+)\.json.*#\1#p')"
if [ -n "$ATT_ID" ]; then
  ATT_URL="https://github.com/${ENTRYPOINT_WORKFLOW_REPO}/attestations/${ATT_ID}"
else
  ATT_URL="https://github.com/${ENTRYPOINT_WORKFLOW_REPO}/attestations"
fi

echo
echo "✅ Attestation SLSA vérifiée et liée à l'image déployée"
echo "   image       : sha256:$D"
echo "   commit      : $COMMIT_URL"
echo "   workflow    : $WORKFLOW_URL"
echo "   builder     : $BUILDER_URL"
echo "   rekor       : $REKOR_URL"
echo "   attestation : $ATT_URL"
echo "   trigger     : $EVENT"
