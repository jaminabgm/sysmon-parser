# HANDOFF

## What we built

A single-file Python CLI (`parser.py`) that parses Sysmon Event ID 1
(Process Creation) XML and extracts a fixed set of fields to JSON:

`EventID`, `UtcTime`, `Image`, `CommandLine`, `User`, `IntegrityLevel`,
`ParentImage`, `ParentCommandLine`, `Computer`, `Hashes`.

It handles two input shapes:
- A bare `<Event>` root (one event) → prints a single JSON object.
- An `<Events>`-wrapped root (multiple events) → prints a JSON array.

It also supports filtering events by four optional flags: `--image`,
`--user`, `--integrity-level`, `--command-line`.

Sample data lives in `samples/`:
- `event1.xml` — a single `whoami /groups` event.
- `multi_events.xml` — three events (`whoami`, `net view /domain`, and
  a base64-encoded PowerShell command) wrapped in `<Events>`.

## How to use it

```bash
# Single event -> JSON object
python3 parser.py samples/event1.xml

# Multiple events -> JSON array
python3 parser.py samples/multi_events.xml

# Filter by process image (substring, case-insensitive)
python3 parser.py samples/multi_events.xml --image powershell

# Filter by user (exact match, case-insensitive)
python3 parser.py samples/multi_events.xml --user "condef\administrator"

# Filter by integrity level (exact match, case-insensitive)
python3 parser.py samples/multi_events.xml --integrity-level high

# Filter by command line — matches if ANY comma-separated substring is present
# NOTE: use --flag=value (not --flag value) when the value starts with "-",
# otherwise argparse mistakes it for another flag.
python3 parser.py samples/multi_events.xml --command-line=-enc,encoded

# Combine filters — all given flags must match (AND across flags)
python3 parser.py samples/multi_events.xml --image powershell --integrity-level high

python3 parser.py --help
```

Output contract: the script always prints valid JSON.
- Multi-event input with no matches → `[]`.
- Single-event input with no match → `null`.

## What's left to do

- No automated test suite — everything so far has been verified by
  manually running `parser.py` against the two sample files and eyeballing
  output (see conversation history / commit message for the specific
  commands run).
- No handling for Sysmon event types other than Event ID 1 (e.g. network
  connections, file creation, registry events).
- No packaging (`requirements.txt`/`pyproject.toml`) — not needed yet since
  the script only uses the standard library, but would matter if this grows.
- Filtering is limited to the four fields above; no filter exists yet for
  `ParentImage`, `ParentCommandLine`, `Hashes`, `UtcTime` ranges, etc.
- No streaming/large-file support — `ET.parse()` loads the whole file into
  memory, which is fine for the current sample sizes but was explicitly
  flagged as a limitation to revisit if large multi-event exports come up.

## Decisions made and why

- **argparse over hand-rolled `sys.argv` parsing** — adopted when filtering
  was added, since it gives free `--help`, standard error messages, and a
  natural place to add optional flags alongside the positional file path.
  Tradeoff accepted: bad-usage exit code changed from a custom `1` to
  argparse's standard `2`.
- **Filtering happens on the parsed field dict, not raw XML** — `parse_event()`
  already normalizes the fields we care about, so `event_matches()` just
  checks the resulting dict. Keeps filtering logic independent of XML
  traversal/namespace handling.
- **AND semantics across different filter flags** — e.g. `--image X
  --user Y` requires both to match. This is the intuitive default for a
  filtering CLI; OR-across-flags wasn't requested and would be surprising.
- **OR semantics within `--command-line`** — a single `--command-line`
  flag accepts a comma-separated list and matches if any one substring is
  present (e.g. `--command-line=-enc,encoded`). This was a deliberate
  exception to the "one value per flag" pattern used by `--image`/`--user`/
  `--integrity-level`, added because a single field sometimes needs
  "contains A or B" logic (e.g. catching both `-enc` and `-EncodedCommand`
  style PowerShell obfuscation).
- **Case-insensitive comparisons everywhere** — Windows file paths and
  account/domain names are case-insensitive by OS convention, so
  `--image powershell` should match `...\PowerShell.exe`. Applied
  consistently to `--integrity-level` too, rather than mixing
  case-sensitivity rules across flags.
- **`null` for a single-event no-match, `[]` for a multi-event no-match** —
  preserves the "always print valid JSON to stdout" contract in both
  shapes, so a caller doing `json.loads(output)` never breaks, instead of
  printing nothing or a non-JSON error for what is fundamentally the same
  "no match" condition.
- **Namespace-stripped tag matching (`strip_ns`)** — Sysmon's XML declares
  the `http://schemas.microsoft.com/win/2004/08/events/event` namespace on
  every element, so tags need namespace stripping before comparing against
  plain strings like `"System"` or `"EventData"`.
