# ProofCanvas

**Turn MCP conformance transcripts into privacy-first, visually clear evidence cards.**

ProofCanvas is a standalone, standard-library-only Python CLI. It reads a text transcript of MCP checks and creates a responsive, printable HTML report with a fail-closed verdict, check-by-check timeline, and a SHA-256 fingerprint **of the normalized, redacted report content**.

The report is **not** independent proof that the remote tool ran. It identifies *user-supplied* results. Reviewers should reproduce tests in their own sandbox.

## Why it exists

MCP demonstrations bury interesting evidence in terminal logs. Builders can also leak endpoint URLs, customer identifiers and tokens when forwarding logs. ProofCanvas solves the presentation problem without uploading or interpreting the underlying execution traces.

Useful for local development, workshops, judges' evidence packs, CI artifacts and review presentations.

## Quick start

Requires Python 3.10 or newer. No pip install, accounts, cloud resources, telemetry, JavaScript build tools or API keys.

~~~sh
python proofcanvas.py --input examples/sample-transcript.txt --output example-evidence.html --label "Synthetic MCP test run"
~~~

Open the generated HTML locally and use **Print or save as PDF** if desired. The example transcript is synthetic; it is not evidence of a real execution.

To convert a *real* conformance output from your own tool:

~~~sh
python proofcanvas.py --input local-checks.txt --output redacted-evidence.html --strict
~~~

The CLI accepts lines of the form NAME = PASS | details. PASS, FAIL, ERROR and SKIP are supported. Non-check lines are ignored and no source content is executed.

## Safety and evidence model

- **Default-deny details:** input details are withheld unconditionally. Known public check types get fixed explanatory captions.
- **Unknown check names anonymized:** any label outside the built-in generic list appears as a numbered CHECK rather than leaking a private identifier.
- **Local-only:** the source is read locally; output is a standalone HTML file without remote assets, fetch, telemetry or network dependencies.
- **No inflated verdict:** any FAIL or ERROR produces FAILED; SKIP without failures produces INCOMPLETE, not PASSED. Exit status 1 in strict mode when a run is not PASSED.
- **No accidental overwrite:** the CLI refuses to overwrite a previous report and bounds input size to 1 MB.
- **HTML escaping:** display labels are escaped.
- **Integrity boundary:** the output SHA-256 covers sanitized, normalized results. It is not a signature, source attestation or proof that an endpoint actually executed.

Protect the original input transcript: it may contain raw values even though they never appear in the report.

## Testing

~~~sh
python -m unittest discover -s tests -v
~~~

CI runs the standard-library unit suite with Python 3.11 and generates synthetic evidence.

## Independent hackathon contribution

This is an **additional open-source developer utility** for the 2026 Amazon Developer Hackathon Open Source mini challenge. It is separate from the primary Alexa+ application [HERMX ProofGate: Recall](https://github.com/senih25/hermx-proofgate-amazon-2026). It does not import or reuse the commercial PBT-G control plane, privileged integrations, user data, or private source.

The utility explains the reported outcome of an MCP conformance run in a legible and privacy-preserving visual format. It does not certify a test. Synthetic sample data are provided.

## Files

- proofcanvas.py — input parser, privacy filters, result computation and self-contained report
- tests/test_proofcanvas.py — standard-library unit tests
- examples/sample-transcript.txt — explicitly synthetic sample input
- .github/workflows/test.yml — GitHub Actions unit-test workflow
- LICENSE — MIT

## Limitations

A transcript can be fabricated. ProofCanvas cannot establish test authenticity, validate remote state, attest endpoint identities or certify security. It supports a compact line-oriented result format rather than every possible MCP client output. Unrecognized check types deliberately lose their original labels.

## License

MIT.
