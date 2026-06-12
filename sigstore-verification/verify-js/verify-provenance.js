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
 *   node verify-provenance.js <repo> <sha256-digest>
 *   node verify-provenance.js aghiles-ait/test-sigstore 0a50000f...969a
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
  const [repo, digestArg] = process.argv.slice(2);
  if (!repo || !digestArg) {
    console.error('Usage: node verify-provenance.js <repo> <sha256-digest>');
    console.error('   ex: node verify-provenance.js aghiles-ait/test-sigstore 0a50000f...969a');
    process.exit(2);
  }
  if (!/^[^/]+\/[^/]+$/.test(repo)) fail(`Repo invalide : attendu 'owner/name', reçu : ${repo}`);

  const D = digestArg.replace(/^sha256:/, '');
  if (!/^[a-f0-9]{64}$/.test(D)) fail(`Digest invalide : attendu 64 hex (sha256), reçu : ${digestArg}`);

  // --- 1) récupérer le bundle depuis GitHub PAR DIGEST (zéro registry) ---
  console.log(`→ Récupération du bundle depuis GitHub (repo: ${repo}, digest: sha256:${D})`);
  const headers = { Accept: 'application/vnd.github+json' };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;

  const resp = await fetch(
    `https://api.github.com/repos/${repo}/attestations/sha256:${D}`,
    { headers }
  );
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) fail(`API GitHub ${resp.status} : ${data.message || resp.statusText}`);

  const bundle = data.attestations?.[0]?.bundle;
  if (!bundle) fail(`Aucune attestation trouvée pour sha256:${D} dans ${repo}`);

  // --- 2) vérif cryptographique : signature + Fulcio + Rekor + émetteur OIDC ---
  console.log('→ Vérification cryptographique (signature + Fulcio + Rekor + issuer)');
  try {
    await verify(bundle, { certificateIssuer: ISSUER });
  } catch (e) {
    fail(`Vérification de signature échouée : ${e.message}`);
  }

  // --- 3) identité du signataire (SAN) via regexp sur le repo ---
  console.log('→ Vérification de l\'identité (SAN du certificat)');
  const san = certSAN(bundle);
  const identityRe = new RegExp(`^URI:https://github\\.com/${repo}/`);
  if (!identityRe.test(san)) {
    fail(`Identité non conforme.\n     attendu (regexp) : ^URI:https://github.com/${repo}/\n     trouvé           : ${san}`);
  }

  // --- 4) binding : subject de l'attestation == digest fourni ---
  console.log('→ Vérification du binding (subject == digest fourni)');
  const payload = decodePayload(bundle);
  const subject = payload.subject?.find((s) => s.digest?.sha256)?.digest.sha256;
  if (subject !== D) {
    fail(`L'attestation parle d'une AUTRE image :\n     attendu : ${D}\n     trouvé  : ${subject}`);
  }

  // --- 5) extraire la source ---
  const dep = payload.predicate?.buildDefinition?.resolvedDependencies?.[0] || {};
  const workflow = payload.predicate?.runDetails?.builder?.id;
  console.log();
  console.log('✅ Attestation SLSA vérifiée et liée à l\'image déployée');
  console.log(`   image    : sha256:${D}`);
  console.log(`   source   : ${dep.uri || '(absent)'}`);
  console.log(`   commit   : ${dep.digest?.gitCommit || '(absent)'}`);
  console.log(`   workflow : ${workflow || '(absent)'}`);
}

main().catch((e) => fail(e.stack || String(e)));
