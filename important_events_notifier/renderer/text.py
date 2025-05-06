#! /usr/bin/env python3
# encoding: utf-8

def render(events = [], link = ""):
    data = {}
    output = "%d new important event(s):\n\n" % len(events)

    # Group by severity
    for event in events:
        if event["severity"] not in data:
            data[event["severity"]] = {}
        if event["type"] not in data[event["severity"]]:
            data[event["severity"]][event["type"]] = {}
        if event["family"] not in data[event["severity"]][event["type"]]:
            data[event["severity"]][event["type"]][event["family"]] = {}
        if event["category"] not in data[event["severity"]][event["type"]][event["family"]]:
            data[event["severity"]][event["type"]][event["family"]][event["category"]] = []
        data[event["severity"]][event["type"]][event["family"]][event["category"]].append(event)

    for severityEvent, level1 in list(data.items()):
        output += "\n# Severity \"%s\"\n" % (severityEvent)
        for typeEvent, level2 in list(level1.items()):
            output += "\n# Type \"%s\"\n" % (typeEvent)
            for familyEvent, level3 in list(level2.items()):
                output += "\n# Family \"%s\"\n" % (familyEvent)
                for categoryEvent, evts in list(level3.items()):
                    output += "\n# Category \"%s\"\n" % (categoryEvent)
                    for evt in evts:
                        output += "- [%s] %s (Id: %s)\n" % (evt["creation_time"].split("+")[0], evt["message"], evt["id"])
                    output += "\n"

    output += "\n\nPlease visit Cisco Cyber Vision backend to obtained more details, ie: %s\n\n" % (link)

    return output
