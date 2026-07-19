# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

A Python tool that parses Sysmon XML event logs and extracts key fields from
Event ID 1 (Process Creation) events.

### Fields extracted

- `EventID`
- `UtcTime`
- `Image` (process path)
- `CommandLine`
- `User`
- `IntegrityLevel`
- `ParentImage`
- `ParentCommandLine`
- `Computer`
- `Hashes`

### Output format

JSON — a single object per event, or a JSON array when parsing multiple events.
