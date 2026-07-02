#!/usr/bin/env node
/*
 * verify-provenance.js — Équivalent JS de verify-provenance.sh, SANS binaire cosign.
 *
 * Vérifie l'attestation SLSA d'une image en pur JS via sigstore-js — aucun accès
 * au registry. Le digest est censé provenir d'une source de confiance (ex. TDX).
 *
 * Étapes :
 *   1. récupère le bundle depuis l'API GitHub (par digest, pas via le registry)
 *   2. vérifie cryptographiquement le bundle : signature + chaîne Fulcio + Rekor
 *      + émetteur OIDC attendu  (sigstore.verify)
 *   3. vérifie l'identité du signataire (SAN) contre une regexp sur le repo
 *   4. confirme que le subject de l'attestation == le digest fourni (binding)
 *   5. affiche le repo source et le commit
 *
 * Usage :
 *   node verify-provenance.js <entrypoint-workflow-repo> <sign-action-repo> <sha256-digest>
 *   node verify-provenance.js aghiles-ait/test-sigstore aghiles-ait/test-sigstore 0a50000f...969a
 *
 * Arguments :
 *   <entrypoint-workflow-repo>  owner/name — repo dont l'événement a déclenché le run
 *                               (détient l'attestation, interrogé via l'API GitHub)
 *   <sign-action-repo>          owner/name — repo du workflow qui SIGNE (le reusable
 *                               workflow). Contraint l'identité du certificat.
 *                               = entrypoint-workflow-repo si la signature n'est pas reusable.
 *   <sha256-digest>             digest de l'image ("sha256:abc..." ou "abc...")
 *
 * Env optionnel :
 *   GITHUB_TOKEN  pour repo privé / éviter le rate-limit anonyme
 */

const { X509Certificate } = require('node:crypto');
const { verify } = require('sigstore');

// Constantes (GitHub Actions keyless + SLSA v1)
const ISSUER = 'https://token.actions.githubusercontent.com';

function fail(msg) {
  console.error(`❌ ${msg}`);
  process.exit(1);
}

function decodePayload(bundle) {
  return JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, 'base64').toString('utf8'));
}

// SAN du certificat de signature -> "URI:https://github.com/.../workflow.yaml@refs/tags/vX"
function certSAN(bundle) {
  const vm = bundle.verificationMaterial;
  const der =
    vm.certificate?.rawBytes ||
    vm.x509CertificateChain?.certificates?.[0]?.rawBytes;
  if (!der) fail("Pas de certificat dans le bundle");
  const cert = new X509Certificate(Buffer.from(der, 'base64'));
  return cert.subjectAltName || '';
}

async function main() {
  const [entrypointWorkflowRepo, signActionRepo, digestArg] = process.argv.slice(2);
  if (!entrypointWorkflowRepo || !signActionRepo || !digestArg) {
    console.error('Usage: node verify-provenance.js <entrypoint-workflow-repo> <sign-action-repo> <sha256-digest>');
    console.error('   ex: node verify-provenance.js aghiles-ait/test-sigstore aghiles-ait/test-sigstore 0a50000f...969a');
    process.exit(2);
  }
  for (const [name, val] of [
    ['entrypoint-workflow-repo', entrypointWorkflowRepo],
    ['sign-action-repo', signActionRepo],
  ]) {
    if (!/^[^/]+\/[^/]+$/.test(val)) fail(`${name} invalide : attendu 'owner/name', reçu : ${val}`);
  }

  const D = digestArg.replace(/^sha256:/, '');
  if (!/^[a-f0-9]{64}$/.test(D)) fail(`Digest invalide : attendu 64 hex (sha256), reçu : ${digestArg}`);

  // --- 1) récupérer le bundle depuis GitHub PAR DIGEST (zéro registry) ---
  // L'attestation est détenue par le repo dont l'événement a déclenché le run.
  console.log(`→ Récupération du bundle depuis GitHub (repo: ${entrypointWorkflowRepo}, digest: sha256:${D})`);
  const headers = { Accept: 'application/vnd.github+json' };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;

  const resp = await fetch(
    `https://api.github.com/repos/${entrypointWorkflowRepo}/attestations/sha256:${D}`,
    { headers }
  );
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) fail(`API GitHub ${resp.status} : ${data.message || resp.statusText}`);

  const attestation = data.attestations?.[0];
  const bundle = attestation?.bundle;
  if (!bundle) fail(`Aucune attestation trouvée pour sha256:${D} dans ${entrypointWorkflowRepo}`);

  // --- 2) vérif cryptographique : signature + Fulcio + Rekor + émetteur OIDC ---
  console.log('→ Vérification cryptographique (signature + Fulcio + Rekor + issuer)');
  try {
    await verify(bundle, { certificateIssuer: ISSUER });
  } catch (e) {
    fail(`Vérification de signature échouée : ${e.message}`);
  }

  // --- 3) identité du signataire (SAN) via regexp sur le repo SIGNATAIRE ---
  // Le SAN = workflow signataire (le reusable workflow s'il y en a un), donc on
  // contraint l'identité au repo du signataire, pas à celui de l'attestation.
  console.log('→ Vérification de l\'identité (SAN du certificat)');
  const san = certSAN(bundle);
  const identityRe = new RegExp(`^URI:https://github\\.com/${signActionRepo}/\\.github/workflows/`);
  if (!identityRe.test(san)) {
    fail(`Identité non conforme.\n     attendu (regexp) : ^URI:https://github.com/${signActionRepo}/\\.github/workflows/\n     trouvé           : ${san}`);
  }

  // --- 4) binding : subject de l'attestation == digest fourni ---
  console.log('→ Vérification du binding (subject == digest fourni)');
  const payload = decodePayload(bundle);
  const subject = payload.subject?.find((s) => s.digest?.sha256)?.digest.sha256;
  if (subject !== D) {
    fail(`L'attestation parle d'une AUTRE image :\n     attendu : ${D}\n     trouvé  : ${subject}`);
  }

  // --- 5) extraire la source ---
  const buildDef = payload.predicate?.buildDefinition || {};
  const dep = buildDef.resolvedDependencies?.[0] || {};
  const entryWf = buildDef.externalParameters?.workflow || {};   // workflow DÉCLENCHEUR
  const builderId = payload.predicate?.runDetails?.builder?.id;   // workflow BUILDER (reusable)
  const event = buildDef.internalParameters?.github?.event_name;

  // Lien cliquable vers l'arborescence du repo à ce commit :
  //   git+https://github.com/<owner>/<repo>@refs/... -> https://github.com/<owner>/<repo>/tree/<sha>
  const commit = dep.digest?.gitCommit;
  const repoUrl = (dep.uri || '').replace(/^git\+/, '').replace(/@.*$/, '');
  const commitUrl = repoUrl && commit ? `${repoUrl}/tree/${commit}` : '(absent)';

  // Lien vers le workflow DÉCLENCHEUR (externalParameters.workflow), pinné au commit source.
  const workflowUrl = entryWf.repository && entryWf.path && commit
    ? `${entryWf.repository}/blob/${commit}/${entryWf.path}`
    : '(absent)';

  // Lien vers le workflow BUILDER (reusable). builder.id = "https://…/<path>@<sha>" -> blob au <sha>.
  let builderUrl = builderId || '(absent)';
  const bMatch = (builderId || '').match(/^https:\/\/github\.com\/([^/]+\/[^/]+)\/(.+)@([^@]+)$/);
  if (bMatch) builderUrl = `https://github.com/${bMatch[1]}/blob/${bMatch[3]}/${bMatch[2]}`;

  // Lien vers l'entrée Rekor (log de transparence) par hash de l'image
  const rekorUrl = `https://search.sigstore.dev/?hash=${D}`;

  // Lien vers l'attestation sur GitHub.
  // NB : l'ID exact n'est pas exposé par l'API ; on le DÉDUIT du bundle_url (.../<id>.json...),
  // format non documenté -> best-effort. Fallback : page liste des attestations (toujours valide).
  const attId = (attestation.bundle_url || '').match(/\/(\d+)\.json/)?.[1];
  const attUrl = attId
    ? `https://github.com/${entrypointWorkflowRepo}/attestations/${attId}`
    : `https://github.com/${entrypointWorkflowRepo}/attestations`;

  console.log();
  console.log('✅ Attestation SLSA vérifiée et liée à l\'image déployée');
  console.log(`   image       : sha256:${D}`);
  console.log(`   commit      : ${commitUrl}`);
  console.log(`   workflow    : ${workflowUrl}`);
  console.log(`   builder     : ${builderUrl}`);
  console.log(`   rekor       : ${rekorUrl}`);
  console.log(`   attestation : ${attUrl}`);
  console.log(`   trigger     : ${event || '(absent)'}`);
}

main().catch((e) => fail(e.stack || String(e)));
