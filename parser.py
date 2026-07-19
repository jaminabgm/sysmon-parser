#!/usr/bin/env python3
import argparse
import json
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
    return parser


def main():
    args = build_arg_parser().parse_args()

    tree = ET.parse(args.path)
    root = tree.getroot()

    if strip_ns(root.tag) == "Events":
        events = [parse_event(e) for e in root if strip_ns(e.tag) == "Event"]
        filtered = [v for v in events
                    if event_matches(v, args.image, args.user, args.integrity_level, args.command_line)]
        print(json.dumps(filtered, indent=2))
    else:
        values = parse_event(root)
        matches = event_matches(values, args.image, args.user, args.integrity_level, args.command_line)
        result = values if matches else None
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
