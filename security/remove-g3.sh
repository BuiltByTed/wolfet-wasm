#!/bin/sh
# Mozilla Bugzilla 2083449: distrust only emSign ECC Root CA - G3.
set -eu
fingerprint=86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B
is_g3() {
    identity=$(openssl x509 -in "$1" -noout -subject -issuer -nameopt RFC2253 2>/dev/null) || return 1
    case "$identity" in
      *'CN=emSign ECC Root CA - G3,'*'O=eMudhra Technologies Limited,'*'C=IN'*)
        actual=$(openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':')
        [ "$actual" = "$fingerprint" ] || { echo 'Unexpected G3 certificate fingerprint' >&2; exit 1; }
        return 0;;
      *) return 1;;
    esac
}
work=$(mktemp -d /tmp/remove-g3.XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
# Disable the Debian anchor as well as removing it. Reinstallation must not
# silently enable this root during a subsequent package operation.
if [ -f /etc/ca-certificates.conf ]; then
    sed -i 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt$|!mozilla/emSign_ECC_Root_CA_-_G3.crt|' /etc/ca-certificates.conf
fi
for directory in /usr/share/ca-certificates /usr/local/share/ca-certificates; do
    [ ! -d "$directory" ] || find "$directory" -type f \( -name '*.crt' -o -name '*.pem' \) >> "$work/anchors"
done
if [ -f "$work/anchors" ]; then
    while IFS= read -r certificate; do
        if is_g3 "$certificate"; then rm "$certificate"; fi
    done < "$work/anchors"
fi
TMPDIR=/tmp update-ca-certificates --fresh
# Python distributions can carry certifi separately from the OS store.
for directory in /usr/local/lib /opt; do
    [ ! -d "$directory" ] || find "$directory" -type f -path '*/certifi/cacert.pem' >> "$work/bundles"
done
printf '%s\n' /etc/ssl/certs/ca-certificates.crt >> "$work/bundles"
while IFS= read -r bundle; do
    [ -f "$bundle" ] || { echo "Missing CA bundle: $bundle" >&2; exit 1; }
    mkdir "$work/parts"
    awk -v dir="$work/parts" '/-----BEGIN CERTIFICATE-----/{n++; out=sprintf("%s/%06d.pem",dir,n)} out {print > out} /-----END CERTIFICATE-----/{close(out);out=""}' "$bundle"
    : > "$work/filtered"
    count=0
    for certificate in "$work"/parts/*.pem; do
        openssl x509 -in "$certificate" -noout >/dev/null
        if ! is_g3 "$certificate"; then cat "$certificate" >> "$work/filtered"; count=$((count+1)); fi
    done
    [ "$count" -gt 0 ] || { echo "Empty trust store: $bundle" >&2; exit 1; }
    cat "$work/filtered" > "$bundle"
    rm -rf "$work/parts"
    printf 'Verified G3 absent: %s (%s certificates)\n' "$bundle" "$count"
done < "$work/bundles"
# Rehash symlinks without enabling disabled anchors again.
openssl rehash /etc/ssl/certs

# G3_RUNTIME_EMBEDDED_FIX: Node can bypass the system bundle with its built-in roots.
if command -v node >/dev/null 2>&1; then
node - <<'G3_NODE_SCRIPT'
'use strict';
// Change only the serialized public CA data in ELF Node executables. Keep all
// code, offsets, string lengths, ownership and other roots unchanged.
// The removed slot repeats an already trusted root; unique trust drops by one.
const fs = require('node:fs');
const crypto = require('node:crypto');
const cp = require('node:child_process');
const target = '86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b';
const libraries = [...new Set((fs.readFileSync("/proc/self/maps", "utf8").match(/\/[^\s]*libnode\.so\.[^\s]+/g) || []))];
const targets = process.argv.length > 2 ? process.argv.slice(2) : [process.execPath, ...libraries];
for (const supplied of new Set(targets)) {
  const file = fs.realpathSync(supplied);
  const before = fs.readFileSync(file);
  if (before.subarray(0, 4).toString('hex') !== '7f454c46') continue;
  const text = before.toString('latin1');
  const certificates = [...text.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)].flatMap(match => {
    try {
      const cert = new crypto.X509Certificate(match[0]);
      return [{ index: match.index, pem: match[0], fingerprint: crypto.createHash('sha256').update(cert.raw).digest('hex') }];
    } catch { return []; }
  });
  const removed = certificates.filter(c => c.fingerprint === target);
  if (!removed.length) { console.log(JSON.stringify({file, removed: 0})); continue; }
  const originalRoots = JSON.parse(cp.execFileSync(file.includes('libnode.so.') ? process.execPath : file, ['-e', 'console.log(JSON.stringify(require("tls").rootCertificates))'],
    {encoding: 'utf8', env: {...process.env, NODE_OPTIONS: ''}, maxBuffer: 4 * 1024 * 1024}));
  const trusted = new Set(originalRoots.map(p => crypto.createHash('sha256').update(new crypto.X509Certificate(p).raw).digest('hex')));
  const replacement = certificates.filter(c => c.fingerprint !== target && trusted.has(c.fingerprint)).sort((a,b) => a.pem.length-b.pem.length)[0];
  if (!replacement || removed.some(c => replacement.pem.length > c.pem.length)) throw new Error('No existing shorter trusted certificate slot');
  const after = Buffer.from(before);
  for (const cert of removed) {
    const data = replacement.pem.padEnd(cert.pem.length, '\n');
    after.write(data, cert.index, cert.pem.length, 'latin1');
  }
  if (after.length !== before.length) throw new Error('Executable length changed');
  const stat = fs.statSync(file), temp = file + '.g3-ca-data.tmp';
  fs.writeFileSync(temp, after, {mode: stat.mode});
  fs.chownSync(temp, stat.uid, stat.gid); fs.chmodSync(temp, stat.mode);
  fs.renameSync(temp, file);
  console.log(JSON.stringify({file, removed: removed.length, replacement: replacement.fingerprint,
    before_sha256:crypto.createHash('sha256').update(before).digest('hex'), after_sha256:crypto.createHash('sha256').update(after).digest('hex')}));
}

G3_NODE_SCRIPT
node -e 'if(require("tls").rootCertificates.some(x=>new (require("crypto").X509Certificate)(x).subject.includes("emSign ECC Root CA - G3")))process.exit(1)'
fi
