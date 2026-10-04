#!/bin/bash
#
# Extracts and decrypts documents from the "backup" collection of the CCDN MongoDB.
#
# Every backup document has the plain-text fields "tan", "site", "usecase", "type"
# ("submission", "report" or "deletion") and "submittedAt" (ISO local date time), plus
# "content", which is encrypted with a hybrid RSA-OAEP-SHA256 + AES-256-CBC scheme
# (see RsaHybridEncryptionServiceImpl in the central-data-node repository).
# A ciphertext too large for a single MongoDB document (> 15 MiB) is not stored in
# "content.ciphertext", but in parts in the collection "largeBackupParts"; "content.ciphertextParts"
# then lists the "_id"s of the parts in order (see MongodbPersistenceServiceImpl.splitEncrypted).
#
# Documents are streamed one by one out of the running "mongodb" service and decrypted
# directly into the target folder, so no encrypted intermediate dump is written.
# Already extracted files are skipped, so an interrupted extraction can be resumed.
#
# Requires on the host: docker compose (with the "mongodb" service running), openssl, base64, od.

set -euo pipefail
umask 077  # decrypted data is sensitive

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEP=$'\x1f'                          # field separator of the rows printed by mongosh
EXPECTED_ALGORITHM="RSA-OAEP-SHA256+AES-256-CBC"
PASSPHRASE_VAR=CCDN_BACKUP_KEY_PASSPHRASE

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Filters (all optional and combined with AND; comma-separated lists match any of the values):
  -t, --tan TAN[,TAN...]         Transfer TAN(s)
  -s, --site CODE[,CODE...]      Site code(s), e.g. UKT,UKFR
  -u, --usecase UC[,UC...]       MTB and/or RD
  -T, --type TYPE[,TYPE...]      submission, report and/or deletion
      --from DATE                submittedAt >= DATE (ISO, e.g. 2026-01-01 or 2026-01-01T12:00)
      --to DATE                  submittedAt <  DATE (exclusive)
      --filter JSON              Additional raw MongoDB filter on the unencrypted fields,
                                 e.g. '{"site": {"\$ne": "UKT"}}'

Options:
  -o, --output DIR               Target folder (prompted for if omitted)
  -k, --key FILE                 RSA private key (PEM; prompted for if omitted)
  -l, --list                     Only list matching documents and the estimated size; decrypts nothing
      --min-free MB              Stop when less than this much space would remain in the
                                 target folder (default: 500)
  -y, --yes                      Don't ask for confirmation
  -h, --help                     Show this help

The key passphrase is prompted for once, or taken from the environment variable $PASSPHRASE_VAR.

Output layout: DIR/<site>/<usecase>/<tan>.<type>.json plus DIR/manifest.tsv
EOF
}

die()  { echo "ERROR: $*" >&2; exit 1; }
warn() { echo "WARNING: $*" >&2; }

confirm() {
  [[ "$ASSUME_YES" == 1 ]] && return 0
  local answer
  read -rp "$1 [y/N] " answer
  [[ "$answer" =~ ^[yYjJ] ]]
}

human() { numfmt --to=iec --suffix=B "$1" 2>/dev/null || echo "$1 bytes"; }

# Replaces everything but a conservative set of characters, so that field values are safe as path components
safe_name() { local s="${1//[^A-Za-z0-9._-]/_}"; echo "${s:-_}"; }


F_TAN="" F_SITE="" F_USECASE="" F_TYPE="" F_FROM="" F_TO="" F_RAW=""
TARGET="" KEY="" LIST_ONLY=0 MIN_FREE_MB=500 ASSUME_YES=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--tan)      F_TAN="$2";     shift 2 ;;
    -s|--site)     F_SITE="$2";    shift 2 ;;
    -u|--usecase)  F_USECASE="$2"; shift 2 ;;
    -T|--type)     F_TYPE="$2";    shift 2 ;;
    --from)        F_FROM="$2";    shift 2 ;;
    --to)          F_TO="$2";      shift 2 ;;
    --filter)      F_RAW="$2";     shift 2 ;;
    -o|--output)   TARGET="$2";    shift 2 ;;
    -k|--key)      KEY="$2";       shift 2 ;;
    -l|--list)     LIST_ONLY=1;    shift ;;
    --min-free)    MIN_FREE_MB="$2"; shift 2 ;;
    -y|--yes)      ASSUME_YES=1;   shift ;;
    -h|--help)     usage; exit 0 ;;
    *)             usage >&2; die "Unknown argument: $1" ;;
  esac
done

[[ "$MIN_FREE_MB" =~ ^[0-9]+$ ]] || die "--min-free must be a number of megabytes"

for cmd in docker openssl base64 od; do
  command -v "$cmd" >/dev/null || die "'$cmd' is required but not installed"
done


# Runs a query against the backup collection. Mode "stats" prints "<count><SEP><ciphertext bytes>",
# "list" prints the plain-text fields and "dump" additionally a problem description (empty if the
# document is fine) and the encrypted content, one document per line. A ciphertext stored in parts
# is reassembled. The last line is always "__END__", so that a truncated stream can be detected.
# Filter values are handed over as environment variables, so they need no quoting/escaping here.
# (Output piped through cat: the snap-installed docker may fail to write into a redirected file)
query_backups() {
  docker compose --project-directory "$REPO_DIR" exec -T \
    -e MODE="$1" -e SEP="$SEP" \
    -e F_TAN="$F_TAN" -e F_SITE="$F_SITE" -e F_USECASE="$F_USECASE" -e F_TYPE="$F_TYPE" \
    -e F_FROM="$F_FROM" -e F_TO="$F_TO" -e F_RAW="$F_RAW" \
    mongodb mongosh --quiet ccdn --eval '
      const e = process.env;
      const list = v => v.split(",").map(s => s.trim()).filter(s => s.length > 0);
      const and = [];
      if (e.F_TAN)     and.push({ tan:     { $in: list(e.F_TAN) } });
      if (e.F_SITE)    and.push({ site:    { $in: list(e.F_SITE) } });
      if (e.F_USECASE) and.push({ usecase: { $in: list(e.F_USECASE) } });
      if (e.F_TYPE)    and.push({ type:    { $in: list(e.F_TYPE) } });
      // submittedAt is an ISO string, so lexicographic comparison is chronological
      if (e.F_FROM)    and.push({ submittedAt: { $gte: e.F_FROM } });
      if (e.F_TO)      and.push({ submittedAt: { $lt:  e.F_TO } });
      if (e.F_RAW)     and.push(EJSON.parse(e.F_RAW));
      const filter = and.length > 0 ? { $and: and } : {};
      const S = e.SEP;
      if (e.MODE === "stats") {
        const r = db.backup.aggregate([
          { $match: filter },
          { $lookup: {
              from: "largeBackupParts", localField: "content.ciphertextParts", foreignField: "_id",
              pipeline: [{ $project: { _id: 0, len: { $strLenBytes: "$ciphertext" } } }], as: "parts"
          } },
          { $group: { _id: null, n: { $sum: 1 }, bytes: { $sum: { $add: [
              { $strLenBytes: { $ifNull: ["$content.ciphertext", ""] } },
              { $sum: "$parts.len" }
          ] } } } }
        ]).toArray();
        print(r.length > 0 ? r[0].n + S + r[0].bytes : "0" + S + "0");
      } else {
        const projection = e.MODE === "dump" ? { _id: 0 } : { _id: 0, content: 0 };
        // Returns [problem, ciphertext]: the ciphertext is either stored directly, or in parts
        const ciphertextOf = d => {
          const c = d.content;
          if (c == null) return ["no content", ""];
          if (typeof c.ciphertext === "string") return ["", c.ciphertext];
          const ids = c.ciphertextParts;
          if (!Array.isArray(ids) || ids.length === 0) return ["neither ciphertext nor ciphertextParts in content", ""];
          const byId = new Map();
          db.largeBackupParts.find({ _id: { $in: ids } }).forEach(p => byId.set(p._id.toHexString(), p));
          const segments = [];
          for (const id of ids) {
            const p = byId.get(id.toHexString());
            if (p == null) return ["ciphertext part " + id.toHexString() + " is missing", ""];
            if (p.tan !== d.tan || p.site !== d.site || p.usecase !== d.usecase || p.type !== d.type)
              return ["ciphertext part " + id.toHexString() + " belongs to another backup", ""];
            segments.push(p.ciphertext);
          }
          return ["", segments.join("")];
        };
        db.backup.find(filter, projection).sort({ submittedAt: 1 }).forEach(d => {
          const fields = [d.tan, d.site, d.usecase, d.type, d.submittedAt];
          if (e.MODE === "dump") {
            const [problem, ciphertext] = ciphertextOf(d);
            const c = d.content || {};
            fields.push(problem, c.algorithm, c.encryptedKey, c.iv, ciphertext);
          }
          print(fields.join(S));
        });
      }
      print("__END__");
    ' | cat
}


# --- Overview ----------------------------------------------------------------------------------

echo "Querying backup collection ..."
stats="$(query_backups stats)" || die "Query failed. Is the mongodb service running? (docker compose up -d mongodb)"
[[ "$(tail -n1 <<<"$stats")" == "__END__" ]] || die "Unexpected response from mongosh:"$'\n'"$stats"
IFS="$SEP" read -r COUNT CIPHER_BYTES <<<"$(head -n1 <<<"$stats")"
# base64 inflates by 4/3; the AES padding (<= 16 bytes per document) is negligible
ESTIMATED_BYTES=$(( CIPHER_BYTES * 3 / 4 ))

echo "Matching documents: $COUNT (decrypted approx. $(human "$ESTIMATED_BYTES"))"
[[ "$COUNT" -gt 0 ]] || exit 0

if [[ "$LIST_ONLY" == 1 ]]; then
  printf 'tan\tsite\tusecase\ttype\tsubmittedAt\n'
  while IFS="$SEP" read -r tan site usecase type submittedAt; do
    [[ "$tan" == "__END__" ]] && exit 0
    printf '%s\t%s\t%s\t%s\t%s\n' "$tan" "$site" "$usecase" "$type" "$submittedAt"
  done < <(query_backups list)
  die "Listing ended unexpectedly"
fi


# --- Target folder -----------------------------------------------------------------------------

if [[ -z "$TARGET" ]]; then
  echo
  echo "Mind the free disk space: decrypted backups are written unencrypted into the target folder."
  read -erp "Target folder: " TARGET
fi
[[ -n "$TARGET" ]] || die "No target folder given"
TARGET="${TARGET/#\~/$HOME}"
mkdir -p "$TARGET"
TARGET="$(cd "$TARGET" && pwd)"

free_bytes() { df -PB1 "$TARGET" | awk 'NR == 2 { print $4 }'; }
MIN_FREE_BYTES=$(( MIN_FREE_MB * 1024 * 1024 ))

echo
df -h "$TARGET"
AVAILABLE=$(free_bytes)
echo "Available: $(human "$AVAILABLE"), needed approx.: $(human "$ESTIMATED_BYTES"), reserve kept free: ${MIN_FREE_MB}MB"

# Filling up the filesystem that holds the Docker data (incl. the MongoDB volume) would affect the running CCDN
if docker_root="$(docker info -f '{{.DockerRootDir}}' 2>/dev/null)" && [[ -n "$docker_root" ]] \
   && [[ "$(df -P "$docker_root" 2>/dev/null | awk 'NR == 2 { print $6 }')" == "$(df -P "$TARGET" | awk 'NR == 2 { print $6 }')" ]]; then
  warn "The target folder is on the same filesystem as the Docker data ($docker_root), i.e. the MongoDB and CCDN data."
  warn "Running out of space there disrupts the running services; prefer a separate disk or mount."
fi

if (( ESTIMATED_BYTES + MIN_FREE_BYTES > AVAILABLE )); then
  warn "Probably not enough space for all documents; extraction stops once the reserve is reached."
  warn "Already extracted files are skipped on a rerun, so you can resume after freeing space."
fi
confirm "Extract $COUNT document(s) to $TARGET?" || exit 1


# --- Private key -------------------------------------------------------------------------------

if [[ -z "$KEY" ]]; then
  read -erp "RSA private key (PEM): " KEY
fi
KEY="${KEY/#\~/$HOME}"
[[ -r "$KEY" ]] || die "Cannot read private key file '$KEY'"
case "$(cd "$(dirname "$KEY")" && pwd)" in
  "$REPO_DIR"*) warn "The private key lies inside the deployment folder; don't keep it on this server after the extraction." ;;
esac

# An unencrypted key accepts an empty passphrase; otherwise ask for it once (or take it from the environment)
if openssl pkey -in "$KEY" -noout -passin pass: 2>/dev/null; then
  PASSIN=(-passin pass:)
else
  if [[ -z "${!PASSPHRASE_VAR:-}" ]]; then
    read -rsp "Passphrase for $KEY: " passphrase; echo
    export "$PASSPHRASE_VAR=$passphrase"
    unset passphrase
  fi
  PASSIN=(-passin "env:$PASSPHRASE_VAR")
  openssl pkey -in "$KEY" -noout "${PASSIN[@]}" 2>/dev/null || die "Wrong passphrase, or not a private key: $KEY"
fi


# --- Extraction --------------------------------------------------------------------------------

MANIFEST="$TARGET/manifest.tsv"
[[ -f "$MANIFEST" ]] || printf 'tan\tsite\tusecase\ttype\tsubmittedAt\tfile\n' > "$MANIFEST"

extracted=0 skipped=0 failed=0 complete=0

# Decrypts one document's content to stdout
decrypt() { # <encryptedKey> <iv> <ciphertext>
  local aes_key_hex iv_hex
  aes_key_hex="$(printf '%s' "$1" | base64 -d | openssl pkeyutl -decrypt -inkey "$KEY" "${PASSIN[@]}" \
      -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 \
    | od -An -v -tx1 | tr -d ' \n')"
  [[ ${#aes_key_hex} -eq 64 ]] || return 1
  iv_hex="$(printf '%s' "$2" | base64 -d | od -An -v -tx1 | tr -d ' \n')"
  printf '%s' "$3" | base64 -d | openssl enc -d -aes-256-cbc -K "$aes_key_hex" -iv "$iv_hex"
}

# The stream is read from fd 3, so that nothing in the loop can accidentally consume it
while IFS="$SEP" read -r -u 3 tan site usecase type submittedAt problem algorithm encryptedKey iv ciphertext; do
  if [[ "$tan" == "__END__" ]]; then complete=1; break; fi

  rel="$(safe_name "$site")/$(safe_name "$usecase")/$(safe_name "$tan").$(safe_name "$type").json"
  out="$TARGET/$rel"
  label="$type $tan ($site/$usecase)"

  if [[ -e "$out" ]]; then
    skipped=$((skipped + 1))
    continue
  fi

  if [[ -n "$problem" ]]; then
    warn "Skipping $label: $problem"
    failed=$((failed + 1))
    continue
  fi

  if [[ "$algorithm" != "$EXPECTED_ALGORITHM" ]]; then
    warn "Skipping $label: unsupported algorithm '$algorithm'"
    failed=$((failed + 1))
    continue
  fi

  needed=$(( ${#ciphertext} * 3 / 4 + MIN_FREE_BYTES ))
  if (( needed > $(free_bytes) )); then
    warn "Stopping: less than ${MIN_FREE_MB}MB would remain in $TARGET."
    break
  fi

  mkdir -p "$(dirname "$out")"
  # Written under a temporary name first, so that no truncated file is mistaken as done on a rerun
  if decrypt "$encryptedKey" "$iv" "$ciphertext" > "$out.part" && mv "$out.part" "$out"; then
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$tan" "$site" "$usecase" "$type" "$submittedAt" "$rel" >> "$MANIFEST"
    extracted=$((extracted + 1))
    (( extracted % 50 == 0 )) && echo "... $extracted extracted"
  else
    rm -f "$out.part"
    warn "Failed to decrypt $label"
    failed=$((failed + 1))
  fi
done 3< <(query_backups dump)

unset "$PASSPHRASE_VAR"

echo
echo "Extracted: $extracted, already present (skipped): $skipped, failed: $failed"
echo "Output: $TARGET (index: $MANIFEST)"
[[ "$complete" == 1 ]] || { warn "Not all matching documents were processed; rerun to resume."; exit 1; }
[[ "$failed" == 0 ]] || exit 1
