#!/usr/bin/env python3
import argparse
import csv
import json
import sys
import xml.etree.ElementTree as ET

FIELDS = [
    "EventID",
    "UtcTime",
    "Image",
    "CommandLine",
    "User",
    "IntegrityLevel",
    "ParentImage",
    "ParentCommandLine",
    "Computer",
    "Hashes",
]


def strip_ns(tag):
    return tag.split("}", 1)[1] if "}" in tag else tag


def parse_event(event_elem):
    values = {field: None for field in FIELDS}

    for child in event_elem:
        if strip_ns(child.tag) != "System":
            continue
        for node in child:
            name = strip_ns(node.tag)
            if name in ("EventID", "Computer"):
                values[name] = node.text

    for child in event_elem:
        if strip_ns(child.tag) != "EventData":
            continue
        for data in child:
            name = data.get("Name")
            if name in FIELDS:
                values[name] = data.text

    return values


def event_matches(values, image=None, user=None, integrity_level=None, command_line=None):
    if image is not None:
        v = values.get("Image")
        if v is None or image.lower() not in v.lower():
            return False
    if user is not None:
        v = values.get("User")
        if v is None or v.lower() != user.lower():
            return False
    if integrity_level is not None:
        v = values.get("IntegrityLevel")
        if v is None or v.lower() != integrity_level.lower():
            return False
    if command_line is not None:
        v = values.get("CommandLine")
        substrs = [s.lower() for s in command_line.split(",")]
        if v is None or not any(s in v.lower() for s in substrs):
            return False
    return True


def compute_stats(events):
    # This stats feature is for quick triage to understand what's in a file before deep analysis
    integrity_counts = {}
    for event in events:
        level = event.get("IntegrityLevel") or "Unknown"
        integrity_counts[level] = integrity_counts.get(level, 0) + 1

    images = sorted({event["Image"] for event in events if event.get("Image")})
    users = sorted({event["User"] for event in events if event.get("User")})
    parent_images = sorted({event["ParentImage"] for event in events if event.get("ParentImage")})

    return {
        "total_events": len(events),
        "unique_images": {"count": len(images), "values": images},
        "unique_users": {"count": len(users), "values": users},
        "unique_parent_images": {"count": len(parent_images), "values": parent_images},
        "events_by_integrity_level": integrity_counts,
    }


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Parse Sysmon XML event log(s) to JSON."
    )
    parser.add_argument("path", help="Path to a Sysmon XML file (<Event> or <Events> root)")
    parser.add_argument("--image", metavar="SUBSTR",
                         help="Only include events whose Image contains SUBSTR (case-insensitive)")
    parser.add_argument("--user", metavar="USER",
                         help="Only include events whose User matches exactly (case-insensitive)")
    parser.add_argument("--integrity-level", metavar="LEVEL",
                         help="Only include events whose IntegrityLevel matches exactly "
                              "(case-insensitive; e.g. High, Medium, Low, System)")
    parser.add_argument("--command-line", metavar="SUBSTR[,SUBSTR...]",
                         help="Only include events whose CommandLine contains any of the "
                              "given comma-separated substrings (case-insensitive)")
    parser.add_argument("--format", choices=["json", "jsonl", "csv"], default="json",
                         help="Output format: json (default), jsonl (one object per line), "
                              "or csv (with headers)")
    parser.add_argument("--stats", action="store_true",
                         help="Print summary statistics (total events, unique images/users/"
                              "parent images, counts by IntegrityLevel) instead of the events "
                              "themselves")
    return parser


def main():
    args = build_arg_parser().parse_args()

    tree = ET.parse(args.path)
    root = tree.getroot()

    is_multi = strip_ns(root.tag) == "Events"
    if is_multi:
        raw_events = [parse_event(e) for e in root if strip_ns(e.tag) == "Event"]
    else:
        raw_events = [parse_event(root)]

    filtered = [v for v in raw_events
                if event_matches(v, args.image, args.user, args.integrity_level, args.command_line)]

    if args.stats:
        print(json.dumps(compute_stats(filtered), indent=2))
    elif args.format == "jsonl":
        for event in filtered:
            print(json.dumps(event))
    elif args.format == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(filtered)
    else:
        # json: preserve the original single-object-vs-array contract based on
        # the source root shape, rather than always flattening to a list like
        # jsonl/csv do.
        if is_multi:
            print(json.dumps(filtered, indent=2))
        else:
            result = filtered[0] if filtered else None
            print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
