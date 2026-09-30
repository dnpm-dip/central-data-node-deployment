# DNPM - Central Clinical Data Node Deployment Setup


**WORK IN PROGRESS**

## How to deploy
After having checked out this repository into a folder on the server, run
"init.sh" to set up some folders, then run "docker compose up -d"

## How to extract site availability logs
With a running docker composite, call "docker compose run --rm siteLogDump". 
This creates a folder called "siteAvailabilityLogDump" inside the "ccdn-data"
docker volume and saves a .json dump named by todays date there.

You can define output filename and a filter query by defining variables like so:
```
FILTER='{\"site\":\"UKJ\"}' FILENAME=ukjLog.json docker compose run --rm siteLogDump
```

## Backup encryption keypair
Submissions, reports and deletion events are backed up into the `backup` collection of the
MongoDB, with their content encrypted (RSA-OAEP-SHA256 + AES-256-CBC hybrid scheme). The CCDN
only needs the **public** key; the private key is only needed for extraction and should be kept
off the server, protected by a passphrase.

Create the keypair once, offline (not on the PROD server):
```
# private key, 4096 bit RSA, AES-256-encrypted with a passphrase (prompts for it)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -aes256 -out private.pem
# public key in X.509 SubjectPublicKeyInfo format ("-----BEGIN PUBLIC KEY-----")
openssl pkey -in private.pem -pubout -out public.pem
```
Copy only `public.pem` to `config/public.pem` of this deployment (the container reads it from
`/ccdn_config/public.pem`, see `CCDN_BACKUP_ENCRYPTION_PUBLIC_KEY_PATH`) and restart the ccdn
service. Without it, the backups fail (logged as errors), everything else keeps working.
Don't use `openssl rsa -RSAPublicKey_out`: its `BEGIN RSA PUBLIC KEY` (PKCS#1) format can't be read by the CCDN.

## How to extract backups
With the mongodb service running, `./backup-extract.sh` streams the matching backup documents out
of the MongoDB and decrypts them directly into a target folder, without an intermediate dump. It
asks for the target folder, shows the free space there and the estimated size of the decrypted
data, and stops before the target filesystem runs full (keeping `--min-free` MB, default 500, free).
Rerunning with the same target folder skips already extracted files, so an interrupted
extraction can be resumed. The private key is asked for (`-k`), as is its passphrase (once).

Filters apply to the unencrypted fields `tan`, `site`, `usecase`, `type` (`submission`, `report`,
`deletion`) and `submittedAt`:
```
# only list what would be extracted, and the estimated size
./backup-extract.sh --list --site UKT,UKFR --usecase MTB
# all submissions of Q1 2026
./backup-extract.sh --type submission --from 2026-01-01 --to 2026-04-01
# raw MongoDB filter on the unencrypted fields
./backup-extract.sh --filter '{"site": {"$ne": "UKT"}}'
```
See `./backup-extract.sh --help` for all options. Output is `<target>/<site>/<usecase>/<tan>.<type>.json`
plus an index `<target>/manifest.tsv`. The decrypted files contain clinical data: delete them
(and the private key) from the server once they're no longer needed.
