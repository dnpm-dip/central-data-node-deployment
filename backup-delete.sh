#!/bin/bash
#
# Manually deletes backed up submissions and reports, identified by their TAN, from the CCDN MongoDB.
#
# For every given TAN, the documents of type "submission" and "report" in the "backup" collection are
# removed, together with their ciphertext parts in "largeBackupParts" and the report in "quarter-reports"
# (like an automatic deletion, see MongodbPersistenceServiceImpl.applyDeletion). Documents of type
# "deletion" or "manual-deletion" are never touched; a warning is printed if any is found.
#
# Each deleted submission-report pair is replaced by one deletion notice in "backup", with the same
# plain-text fields as every backup document: "tan", "site", "usecase" (taken from the deleted
# documents), "type" ("manual-deletion"), "submittedAt" (time of the deletion, like for automatic
# deletion events) and "content", which is not encrypted here, but holds the given comment.
#
# Every TAN must have exactly one submission and one report, with equal "site", "usecase" and
# "submittedAt"; otherwise nothing at all is deleted. With --no-pair-check, the TAN's documents are
# deleted anyway, and one notice is inserted per distinct "site" and "usecase" among them.
#
# Requires on the host: docker compose (with the "mongodb" service running).

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEP=$'\x1f'                          # field separator of the rows printed by mongosh

usage() {
  cat <<EOF
Usage: $(basename "$0") [options] [TAN...]

Deletes the backed up submission and report of each given TAN, and inserts a deletion notice
of type "manual-deletion" for each of them instead.

Options:
  -t, --tan TAN[,TAN...]         TAN(s) to delete (may be combined with TANs as arguments)
  -c, --comment TEXT             Comment stored as "content" of the deletion notices
                                 (default: "no-comment")
      --no-pair-check            Don't require exactly one submission and one report with
                                 matching "site", "usecase" and "submittedAt" per TAN
  -n, --dry-run                  Only show what would be deleted and inserted
  -y, --yes                      Don't ask for confirmation
  -h, --help                     Show this help
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


TANS="" COMMENT="no-comment" PAIR_CHECK=1 DRY_RUN=0 ASSUME_YES=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--tan)        TANS="$TANS,$2"; shift 2 ;;
    -c|--comment)    COMMENT="$2";    shift 2 ;;
    --no-pair-check) PAIR_CHECK=0;    shift ;;
    -n|--dry-run)    DRY_RUN=1;       shift ;;
    -y|--yes)        ASSUME_YES=1;    shift ;;
    -h|--help)       usage; exit 0 ;;
    -*)              usage >&2; die "Unknown argument: $1" ;;
    *)               TANS="$TANS,$1"; shift ;;
  esac
done

[[ "${TANS//[ ,]/}" != "" ]] || { usage >&2; die "No TAN given"; }
[[ -n "$COMMENT" ]] || die "Empty comment given"

command -v docker >/dev/null || die "'docker' is required but not installed"

# "submittedAt" of the notices: German local time, formatted like Java's ISO_LOCAL_DATE_TIME
TIMEZONE="Europe/Berlin"


# Checks the documents of the TANs and, in mode "plan", prints what would be deleted and inserted,
# in mode "apply" deletes them and inserts the notices (only if all checks pass).
# Prints one message per line as "<INFO|WARN|ERROR><SEP><text>", then "SUMMARY<SEP><number of failed
# checks><SEP><number of notices>" and finally "__END__", so that a truncated response can be detected.
# MongoDB runs without replica set, i.e. without transactions, so each TAN is processed on its own:
# the notice is inserted first, so that a failure in between leaves no deletion undocumented.
# Values are handed over as environment variables, so they need no quoting/escaping here.
# (Output piped through cat: the snap-installed docker may fail to write into a redirected file)
run_deletion() { # <plan|apply> [submittedAt]
  docker compose --project-directory "$REPO_DIR" exec -T \
    -e MODE="$1" -e SEP="$SEP" -e TANS="$TANS" -e COMMENT="$COMMENT" -e PAIR_CHECK="$PAIR_CHECK" \
    -e SUBMITTED_AT="${2:-}" \
    mongodb mongosh --quiet ccdn --eval '
      const e = process.env;
      const S = e.SEP;
      const out = (kind, text) => print(kind + S + text);
      const ENTITY_TYPES = ["submission", "report"];
      const describe = d => `${d.type} (${d.site}/${d.usecase}, submitted ${d.submittedAt})`;
      const tans = [...new Set(e.TANS.split(",").map(s => s.trim()).filter(s => s.length > 0))];

      // Per TAN, the submissions and reports grouped by "site" and "usecase"; each group is
      // replaced by one deletion notice
      const groups = [];
      let errors = 0;
      for (const tan of tans) {
        const docs = db.backup.find({ tan }, { content: 0 }).sort({ type: -1 }).toArray();
        const entities = docs.filter(d => ENTITY_TYPES.includes(d.type));
        docs.filter(d => !ENTITY_TYPES.includes(d.type))
          .forEach(d => out("WARN", `TAN ${tan}: found ${describe(d)}, which is left untouched`));
        if (entities.length === 0) {
          out("WARN", `TAN ${tan}: no submission or report found, nothing to delete`);
          continue;
        }
        const submissions = entities.filter(d => d.type === "submission");
        const reports     = entities.filter(d => d.type === "report");
        const problems = [];
        if (submissions.length !== 1 || reports.length !== 1)
          problems.push(`expected one submission and one report, found ${submissions.length} submission(s) and ${reports.length} report(s)`);
        else
          for (const f of ["site", "usecase", "submittedAt"])
            if (submissions[0][f] !== reports[0][f])
              problems.push(`"${f}" differs between submission ("${submissions[0][f]}") and report ("${reports[0][f]}")`);
        if (problems.length > 0 && e.PAIR_CHECK === "1") {
          problems.forEach(p => out("ERROR", `TAN ${tan}: ${p}`));
          errors++;
          continue;
        }
        problems.forEach(p => out("WARN", `TAN ${tan}: ${p} (pair check disabled)`));
        const byKey = new Map();
        for (const d of entities) {
          const key = JSON.stringify([d.site, d.usecase]);
          if (!byKey.has(key)) byKey.set(key, { tan, site: d.site, usecase: d.usecase, docs: [] });
          byKey.get(key).docs.push(d);
        }
        groups.push(...byKey.values());
      }

      const entityFilter = g => ({ tan: g.tan, site: g.site, usecase: g.usecase, type: { $in: ENTITY_TYPES } });
      const quarterReportFilter = g => ({ id: g.tan, "site.code": g.site, useCase: g.usecase });
      const quarterReports = db.getCollection("quarter-reports");

      if (e.MODE === "plan") {
        for (const g of groups) {
          out("INFO", `TAN ${g.tan} (${g.site}/${g.usecase}):`);
          g.docs.forEach(d => out("INFO", `  delete ${describe(d)}`));
          const parts    = db.largeBackupParts.countDocuments(entityFilter(g));
          const quarters = quarterReports.countDocuments(quarterReportFilter(g));
          out("INFO", `  delete ${parts} ciphertext part(s) and ${quarters} quarter report(s)`);
          out("INFO", `  insert manual-deletion notice`);
        }
      } else if (errors === 0) {
        for (const g of groups) {
          // same fields in the same order as MongodbPersistenceServiceImpl.storeBackup
          db.backup.insertOne({
            tan: g.tan, site: g.site, usecase: g.usecase, type: "manual-deletion",
            content: e.COMMENT, submittedAt: e.SUBMITTED_AT
          });
          const deleted  = db.backup.deleteMany(entityFilter(g)).deletedCount;
          // after the backup documents, so that none is left pointing to removed parts
          const parts    = db.largeBackupParts.deleteMany(entityFilter(g)).deletedCount;
          const quarters = quarterReports.deleteMany(quarterReportFilter(g)).deletedCount;
          out("INFO", `TAN ${g.tan} (${g.site}/${g.usecase}): inserted manual-deletion notice, deleted ` +
                      `${deleted} backup document(s), ${parts} ciphertext part(s) and ${quarters} quarter report(s)`);
        }
      }
      out("SUMMARY", errors + S + groups.length);
      print("__END__");
    ' | cat
}

# Prints the messages of a response of run_deletion and sets N_ERRORS and N_NOTICES from its summary.
# Fails if the response is incomplete.
show_response() { # <response>
  local kind text
  N_ERRORS="" N_NOTICES=""
  while IFS="$SEP" read -r kind text; do
    case "$kind" in
      INFO)    echo "$text" ;;
      WARN)    warn "$text" ;;
      ERROR)   echo "ERROR: $text" >&2 ;;
      SUMMARY) IFS="$SEP" read -r N_ERRORS N_NOTICES <<<"$text" ;;
      __END__) return 0 ;;
      *)       echo "$kind${text:+$SEP$text}" ;;
    esac
  done <<<"$1"
  return 1
}


echo "Checking backup collection ..."
response="$(run_deletion plan)" || die "Query failed. Is the mongodb service running? (docker compose up -d mongodb)"
show_response "$response" || die "Unexpected response from mongosh"
echo

if [[ "$N_ERRORS" != 0 ]]; then
  die "$N_ERRORS TAN(s) failed the check above, nothing was deleted. Use --no-pair-check to delete anyway."
fi
if [[ "$N_NOTICES" == 0 ]]; then
  echo "Nothing to delete."
  exit 0
fi
[[ "$DRY_RUN" == 1 ]] && exit 0

echo "Comment of the deletion notice(s): $COMMENT"
confirm "Delete the documents listed above and insert $N_NOTICES deletion notice(s)?" || exit 1

echo
response="$(run_deletion apply "$(TZ="$TIMEZONE" date +%Y-%m-%dT%H:%M:%S.%3N)")" || true
show_response "$response" \
  || die "Deletion aborted by an error; only the TANs reported above as done were processed."
if [[ "$N_ERRORS" != 0 ]]; then
  die "The documents changed since the check, $N_ERRORS TAN(s) failed it now; nothing was deleted."
fi
echo
echo "Inserted $N_NOTICES manual-deletion notice(s)."
