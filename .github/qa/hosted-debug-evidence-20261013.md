# Hosted Linux Debug evidence: 2026-10-13

This records the limited Runtime-only Linux x64 result in
[run 38342884977](https://github.com/Floorp-Projects/Floorp-Runtime/actions/runs/38342884977).
The run used code revision `d84cacd368a07b9f47506ea338e0ded6f54a1c05`, branch
`codex/qa3-actions-native-proof-qa337-16`, attempt 1 and BuildID
`20261013034119`. All five jobs succeeded. The 104 host contract methods passed
with zero skips; they are separate from the four native cases below.

## Original evidence and independent checks

The preserved diagnostic copy is `qa3-38342884977-verified-evidence.zip`,
2,517,252 bytes, SHA256
`b350f493c9718b4ec2dbf6d8dc9952087e433e2eeb1b4b082c16b96f8424b7c2`.
It contains these original GitHub ZIPs and a verification summary:

| Artifact                                 | GitHub ID   |   Bytes | SHA256                                                             |
| ---------------------------------------- | ----------- | ------: | ------------------------------------------------------------------ |
| `qa3-boundary-probe-38342884977-1`       | 11787781211 |    9017 | `28de2d62c498de933706c866db3b6fc1863d5bccf3049da85843f10dca14f2a9` |
| `qa3-consumer-evidence-38342884977-1`    | 11791275994 |   72538 | `5ca55aa5e9a83a5046c44510ba08979c6228af0f991ab220fb8bff155b33a378` |
| `qa3-producer-diagnostics-38342884977-1` | 11790278410 | 2458069 | `bdea58be2fba0548babaccf985f7eeff421ce58a5e97fb0132a43a740e7a8785` |

The receiving workspace independently checked the copy's bytes, all three
original digests, ZIP CRCs, unique safe paths and regular-file types. The
consumer ZIP contains 32 files; its export manifest binds 26 files. Each bound
file's bytes and SHA256 matched the manifest and root supervision receipt.
The unchanged `qa3_mozlog.py` from the successful revision replayed all four
complete raw mozlogs and reproduced the recorded verdicts without launching a
browser or repeating a native test.

## Executed subset

| Suite          | Exact test ID                                                             | Assertions | Exit | Verdict              |
| -------------- | ------------------------------------------------------------------------- | ---------: | ---: | -------------------- |
| browser-chrome | `browser/base/content/test/performance/browser_hiddenwindow_existence.js` |          1 |    0 | `PASS`               |
| browser-chrome | `browser/base/content/test/performance/browser_qa3_assertion.js`          |          1 |    1 | `EXPECTED_REJECTION` |
| xpcshell       | `xpcom/tests/unit/test_nsIMutableArray.js`                                |         49 |    0 | `PASS`               |
| xpcshell       | `xpcom/tests/unit/test_qa3_assertion.js`                                  |          1 |    1 | `EXPECTED_REJECTION` |

Both canaries identify `QA3_EXPECTED_ASSERTION`. Every case has a complete suite
and test lifecycle, one execution, a matching supervised raw-log identity and
successful owned-process cleanup. The expected failures verify rejection and
are not product-test passes. Empty, skipped, retried, crashed or truncated
results cannot satisfy this fixed selection.

## Producer and consumer subjects

The producer's effective configuration before and after test packaging enables
tests, Debug and native compilation, targets `x86_64-pc-linux-gnu`, and excludes
artifact builds and PGO generate/use. Common, mochitest and xpcshell archives
come from the same Debug OBJDIR. Its compiled ELF identities and declared
source-delta digest are unchanged after test packaging.

The producer receipt remains `PACKAGED_NOT_CONSUMED`; it is not rewritten when
the later consumer succeeds. The consumer receipt binds the same run, attempt,
Runtime recipe and BuildID, and a different boot identity. The separate boundary
probe reports `PASS_BOUNDARY_ONLY`. The cold consumer uses an ephemeral nonroot
account, fresh state and offline dependencies. Its recorded scope limits are
four CPU cores, 14 GiB memory, no swap and 512 processes. The root final receipt
reports service exit 0 and an empty scope after stop.

The collected result is `PASS_DEBUG_HARNESS_ONLY`, while
`nativeProductQualification=UNVERIFIED` and `publicationAuthorized=false`.
The public GitHub producer and hosted Blacksmith consumer constitute this
profile; the result does not certify the separate private full-native launcher
or a private producer boundary.

## Limits and next stages

The received copy contains diagnostics and receipts, not the full primary
binary package, support package or offline wheel environment. Their complete
bytes were consumed and checked by the successful CI recipe; they were not
independently re-extracted during this documentation handoff. Original failures
from earlier attempts remain separate history. This run does not establish
broad Firefox coverage, Floorp overlay/E2E coverage, PGO-specific behavior,
five-target qualification, final signed/transformed artifact qualification or
publication authorization.

The upstream metadata pins Firefox 157.0.1 to canonical Git revision
`0c469c2352451630bc69fc328c9f0c589c6c534d`. Independent mapping to an official
Firefox distribution's Mercurial source stamp remains unverified. No PGO
generate/profile/use subject from this campaign proves a shared source cohort.

Continue QA3-03 with a reviewed broader Runtime subset; implement QA3-06 for
Floorp features against exact packaged products; then extend QA3-07/08 to all
native targets and authenticated source/profile qualification. QA3-09 retains
the intended `bundle -> final QA -> manual approval -> fresh evidence
revalidation -> publish` chain. Agentic QA in QA3-10 remains bounded exploration
with independent oracles, fixed replay and regression candidates.

The successful code SHA above remains the evidence subject when documentation
or integration commits follow it. Record each new HEAD separately; do not
assign this run to changed code, replay its creation-only branch or infer a new
native qualification from lightweight PR CI. Total spend within the US$10
campaign budget remains pending the complete billing ledger.
