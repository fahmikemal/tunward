# Publication and exposed-key history

Three private-key blobs were found in the original reachable history: the old
development CA, server, and client keys under `certs/mTLS/private`. Removing the
current files and adding ignore rules does not remove prior commits. Any such
key must be considered exposed wherever it was deployed. Rotate/revoke affected
identities and trust before relying on history cleanup.

## Check the release source

~~~sh
python3 scripts/check_publication.py
python3 scripts/check_publication.py --history
~~~

The first command inspects indexed working-tree files; the second inspects every
reachable Git blob. They report paths/object IDs without printing private-key
material. This is a PEM-marker check, not a general credential scanner or proof
that unreachable objects, hosted caches, forks, old images, or downloaded copies
have been erased. Keep the existing Gitleaks scan and review other secret types
separately. Untracked files are not covered by the indexed check.

## Prepare a separate cleaned copy

The following operates only on a new mirror. It does not change a dirty working
tree or publish anything. For a local source, `--no-local` avoids shared object
storage. Choose a new output path and protect the output directory, which may
contain sensitive data until filtering and verification finish.

~~~sh
mkdir -m 700 target/publication-review
git clone --mirror --no-local . target/publication-review/history-clean.git
git -C target/publication-review/history-clean.git filter-repo \
  --sensitive-data-removal --no-fetch --invert-paths \
  --path certs/mTLS/private/ --path certs/mTLS/certs/ \
  --path certs/mTLS/csr/ --path certs/mTLS/newcerts/ \
  --path certs/mTLS/index.txt --path certs/mTLS/index.txt.attr \
  --path certs/mTLS/serial
python3 scripts/check_publication.py \
  --repository target/publication-review/history-clean.git --history
~~~

This bounded recipe removes the known historical generated paths. Search for
renamed/copied sensitive files and other credential types before publication.
`--no-fetch` preserves the local ref snapshot; it does not prove that all remote
refs were present locally. Inspect the mirror's refs and `filter-repo` commit map
against the actual hosting repository. A local mirror contains committed history,
not current uncommitted implementations or untracked documentation.

On 2026-10-21, the published `main` history was replaced using an exact
expected-head lease. Twelve commits were rewritten; the cleaned base contains
138 reachable blobs with no PEM private-key findings. The replacement base is
`078e7bd6340b7a7a9156b314cc7473923e22f622`. The beta implementation is reviewed
separately on a branch descended from that base. These counts describe the
cleaned base, not subsequent commits or hidden hosted refs.

If you cloned before this cutover, make a fresh clone and reapply only reviewed
source changes. Do not merge or push the old branch history into the cleaned
repository. An operator-only recovery bundle is retained outside the published
source; it still contains exposed material and must remain private.

## Coordinated hosting cutover

Before changing hosted history, finalize and review the desired release source,
freeze competing pushes, record the current remote refs, and prepare the exact
rewritten branch/tag mapping. Recreate signatures that rewriting invalidates.
Use explicitly reviewed ref updates against the recorded remote heads; do not
blindly mirror-push a partial local snapshot, which can delete or overwrite refs
that were not fetched. Account for branch protections and other maintainers'
work. Preserve an operator-controlled recovery reference without redistributing
the exposed material.

After publishing rewritten refs, follow the host's sensitive-data removal process
for pull-request refs and caches that ordinary Git pushes cannot update. Coordinate
fresh clones or deliberate cleanup for collaborators, CI caches, forks, release
assets, and image layers. Do not merge old history back into the rewritten graph.
A force push cannot revoke a certificate or erase another person's copy.

The release workflow checks reachable history before publishing. The branch
rewrite does not establish that GitHub caches, hidden refs, forks, or old clones
have been purged. Host-side removal and rotation/revocation of any deployed old
keys remain separate follow-up work. Publishing the beta branch also does not
establish production qualification; see [qualification status](STAGING_QUALIFICATION.md).

See the primary [git-filter-repo manual](https://github.com/newren/git-filter-repo/blob/main/Documentation/git-filter-repo.txt)
and [GitHub sensitive-data removal guide](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).
