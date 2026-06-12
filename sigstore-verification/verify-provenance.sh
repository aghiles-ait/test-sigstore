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
#   ./verify-provenance.sh <repo> <sha256-digest>
#   ./verify-provenance.sh aghiles-ait/test-sigstore 0a50000fc886c537e42d1a953449be0d37af9a2f6fb296a55cdf11403110969a
#
# Variables d'environnement optionnelles :
#   GITHUB_TOKEN  pour repo privé / éviter le rate-limit anonyme

set -euo pipefail

# Constantes (GitHub Actions keyless + SLSA v1)
ISSUER="https://token.actions.githubusercontent.com"
PREDICATE="slsaprovenance1"

# --- arguments -------------------------------------------------------------
if [ $# -ne 2 ]; then
  echo "Usage: $0 <repo> <sha256-digest>" >&2
  echo "   ex: $0 aghiles-ait/test-sigstore 0a50000f...969a" >&2
  exit 2
fi

REPO="$1"

# Accepte aussi bien "sha256:abc..." que "abc..."
D="${2#sha256:}"

if ! printf '%s' "$REPO" | grep -Eq '^[^/]+/[^/]+$'; then
  echo "❌ Repo invalide : attendu 'owner/name', reçu : $REPO" >&2
  exit 2
fi

if ! printf '%s' "$D" | grep -Eq '^[a-f0-9]{64}$'; then
  echo "❌ Digest invalide : attendu 64 caractères hex (sha256), reçu : $1" >&2
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
echo "→ Récupération du bundle depuis GitHub (repo: $REPO, digest: sha256:$D)"
AUTH=()
[ -n "${GITHUB_TOKEN:-}" ] && AUTH=(-H "Authorization: Bearer $GITHUB_TOKEN")
curl -sS "${AUTH[@]+"${AUTH[@]}"}" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/$REPO/attestations/sha256:$D" -o "$RESP"

jq '.attestations[0].bundle' "$RESP" > "$BUNDLE" 2>/dev/null || true
if [ ! -s "$BUNDLE" ] || [ "$(cat "$BUNDLE")" = "null" ]; then
  echo "❌ Aucune attestation trouvée pour sha256:$D dans $REPO" >&2
  jq -r '.message // empty' "$RESP" 2>/dev/null | sed 's/^/   GitHub: /' >&2 || true
  exit 1
fi

# --- 2) vérifier signature + identité depuis le bundle seul ----------------
# --certificate-identity= reference of the workflow who built the image
                                                                                    
echo "→ Vérification de la signature (cert Fulcio + Rekor, hors-ligne)"
cosign verify-blob-attestation \
  --new-bundle-format \
  --bundle "$BUNDLE" \
  --type "$PREDICATE" \
  --certificate-identity-regexp "^https://github.com/$REPO/" \
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
WORKFLOW="$(printf '%s' "$PAYLOAD" | jq -r '.predicate.runDetails.builder.id')"

echo
echo "✅ Attestation SLSA vérifiée et liée à l'image déployée"
echo "   image    : sha256:$D"
echo "   source   : $URI"
echo "   commit   : $COMMIT"
echo "   workflow : $WORKFLOW"
