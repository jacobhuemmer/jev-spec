# Security review — 2026-09-28

The fork is not ready to use as a required security or specification gate. The
upstream tests pass and npm reports no known dependency vulnerabilities, but
additional adversarial tests reproduce gaps that allow checks to pass with
malformed answers or incomplete source coverage.

No application fixes have been made. This branch adds reproducible probes and
receipts so fixes can be tested against the exact failures before adoption.

## Scope and isolation

- Upstream source: `b33961d2cbfee3a93444bd4ed3258a62884d484e`.
- Published artifact: `jev-spec@0.3.0`, npm gitHead
  `8cd750650e6e9532c1877e286d867cefa1eace2c`. SHA-512 integrity was verified against
  npm metadata. npm advertises a provenance attestation; its signature was not
  independently verified. The relevant source differs only in CLI help wording.
- Node `v24.21.0` and Bun `1.4.2`, Linux ARM64 in Docker/OrbStack.
- Only the public fork was mounted, read-only. Work happened in a container copy.
  The host home directory, credentials, Docker socket, and SES files were not
  mounted. Linux capabilities were dropped and privilege escalation disabled.
- Dependencies were installed from the lockfile with `npm ci --ignore-scripts`.
  The dependency audit ran online. Then the container was disconnected from all
  Docker networks before source execution and tests. A loopback HTTP server
  inside the container simulated TypeSafe responses; no TypeSafe API was called.
- Every fixture, source-embedded secret, environment value, and API key in these
  probes is synthetic. The package was not installed into the workstation's
  normal Node environment or integrated with any private repository.

## Results

| Check | Result |
|---|---|
| `npm audit` against the committed lockfile | 0 reported vulnerabilities |
| Upstream `npm run check` on Node 24 | Lint and type checking pass; 149 tests pass |
| Upstream `bun run pretest` and `bun test` | 149 tests pass |
| Additional probes on source / Node 24 | 6 controls pass; 8 security expectations fail |
| Additional probes on source / Bun | Same 6 passes and 8 failures |
| Additional probes on published npm 0.3.0 / Node 24 | Same 6 passes and 8 failures |

Passing controls cover root traversal, escaping symlinks, escaping report
destinations, Git argument injection, default sensitive-file exclusions, custom
URLs without opt-in, and missing evaluator answers. A passing audit means no
known advisories were reported for these versions; it does not prove that
packages are benign or that every vulnerability has been found.

## Reproduced gaps

Severity below describes the risk when this tool is trusted as a required gate;
these are review assessments, not assigned CVEs.

| Finding | Probe | Assessment | Evidence and effect |
|---|---|---|---|
| Git-quoted filenames bypass diff selection | `DIFF-01` | High for a required PR gate | A modified `src/é.ts` under Git's normal `core.quotePath=true` is not parsed. The target is marked skipped and the overall run passes, even though a rejecting evaluator would fail it. |
| Oversized matched source is silently omitted | `CONTEXT-01` | Medium | A source file over 2 MiB is omitted; the evaluator receives zero code characters and can return a passing answer. No source-size error stops the real run. |
| Truncated context can yield an unqualified pass | `CONTEXT-02` | Medium | Code beyond the 120,000-character context budget is not evaluated. A synthetic positive evaluator produces a pass; the real-run report does not expose the truncation warning that dry runs expose. |
| Malformed API probabilities can pass assertions | `ANSWER-01`–`ANSWER-04` | Medium | Through the real TypeSafe SDK and a loopback server, `null`, the string `"0.99"`, and out-of-range values `2` and `-1` can pass thresholds. `Number(...)` coercion and finite-only validation accept these values. |
| Custom endpoint opt-in uses truthiness | `URL-01` | Low by itself | JavaScript configuration with `allowCustomBaseUrl: "false"` enables a custom URL. Runtime validation does not require the flag to be boolean. That endpoint receives the API key and selected source. A TypeScript type error is not a runtime defense for JavaScript configs. |

The context probes demonstrate missing coverage enforcement, not that the live
Jev service will necessarily approve those particular fixtures. The malformed
answer probes use fabricated server responses; they do not establish that
TypeSafe currently returns such answers. The filename bypass requires neither
a live API nor a fabricated API response: the evaluator is never called.

## Trust boundaries observed

These are architectural risks rather than evidence of malicious project code:

- `TRUST-01`: Selected source text reaches the API without content-based secret
  redaction. Default filename exclusions are useful but do not remove a secret
  embedded in an otherwise ordinary source file. Live use sends the selected
  specification and code to TypeSafe.
- `TRUST-02`: `--dry-run` imports and executes the JavaScript/TypeScript config.
  The probe writes a harmless marker from a synthetic environment value, proving
  that config code can access process credentials and perform side effects.
  The project's root-path checks do not sandbox this code. Untrusted checkouts
  must be isolated even for dry runs, with no real credentials available.
- `TRUST-03`: Closing prompt-boundary tags inside source text are not escaped.
  This is a structural observation only. No live prompt-injection success was
  measured; framing instructions should not be treated as a security boundary.
- `.github/workflows/jev-spec.yml` provides the API key at job scope, including
  dependency installation and the build. Keep credentials confined to a trusted
  evaluation step rather than exposing them to the entire job. Same-repository
  PRs can change executable config, dependencies, build scripts, and thresholds;
  deciding that a PR is trusted requires more than checking whether it is a fork.

## Before adoption

1. Fix filename handling using Git's NUL-delimited name/status output instead of
   parsing display-oriented unified-diff headers.
2. Reject incomplete code context, or require an explicit, visible acceptance of
   omissions. A required gate must not silently pass an unexamined implementation.
3. Validate API answer types and allowed ranges before coercion, and require
   boolean client options at runtime. Test Choice and Score response validation
   when implementing the fix too.
4. Keep config and rubric changes reviewable. Execute untrusted checkouts only in
   disposable, unprivileged environments without credentials. Provide the live
   API key only after the configuration and selected files are trusted.
5. For private repositories, determine which content may be sent to TypeSafe and
   the applicable retention terms. Use narrow file selection and a secret scan
   before network submission. Begin with advisory results alongside real tests.
6. Pin the package, dependency lockfile, model version, and CI action commits.
   Prefer the reviewed local package over an unpinned `npx` download.

## Reproduce

Run from the fork root. The commands copy the public checkout into the container;
they do not execute the package on the host. The image tag and container name are
examples; choose new names if these already exist.

```sh
mkdir -p security-results
docker build -t jev-spec-review -f security-review/Dockerfile .
docker run -d --name jev-spec-review \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 256 --memory 2g --cpus 2 \
  --mount type=bind,src="$PWD",dst=/source,readonly \
  --mount type=bind,src="$PWD/security-results",dst=/results \
  --workdir /workspace jev-spec-review \
  sh -c 'cp -R /source/. /workspace/ && git config --global --add safe.directory /workspace && sleep infinity'
docker exec jev-spec-review npm ci --ignore-scripts
docker exec jev-spec-review sh -c 'npm audit --json > /results/npm-audit.json'
docker network disconnect bridge jev-spec-review
docker exec jev-spec-review npm run check
docker exec jev-spec-review node security-review/adversarial.mjs /results/adversarial.json
# The adversarial suite intentionally exits 1 while findings remain.
docker rm -f jev-spec-review
```

`results/` contains the audit and all three adversarial receipts. Complete
installation and baseline logs from this run are local under
`~/.local/state/jev-spec-security/2026-09-28/`.

This was a targeted source and behavior review. It did not audit every transitive
dependency's source, verify all supply-chain attestations, scan the container
image for operating-system advisories, run Node 22/Windows/macOS-native tests, or
evaluate live Jev prompt resistance. No security certification is implied.
