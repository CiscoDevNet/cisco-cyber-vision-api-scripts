#! /usr/bin/env python3
# encoding: utf-8

def render(events = [], link = ""):
    data = {}
    output = "%d new important event(s):\n" % len(events)

    # Group by severity
    for event in events:
        if event["severity"] not in data:
            data[event["severity"]] = {}
        if event["type"] not in data[event["severity"]]:
            data[event["severity"]][event["type"]] = {}
        if event["family"] not in data[event["severity"]][event["type"]]:
            data[event["severity"]][event["type"]][event["family"]] = {}
        if event["category"] not in data[event["severity"]][event["type"]][event["family"]]:
            data[event["severity"]][event["type"]][event["family"]][event["category"]] = {}
        if event["short_message"] not in data[event["severity"]][event["type"]][event["family"]][event["category"]]:
            data[event["severity"]][event["type"]][event["family"]][event["category"]][event["short_message"]] = 1
        else:
            nbOccur = data[event["severity"]][event["type"]][event["family"]][event["category"]][event["short_message"]]
            data[event["severity"]][event["type"]][event["family"]][event["category"]][event["short_message"]] = (nbOccur + 1)

    for severityEvent, level1 in data.items():
        output += "# Severity \"%s\"\n" % (severityEvent)
        for typeEvent, level2 in level1.items():
            output += "# Type \"%s\"\n" % (typeEvent)
            for familyEvent, level3 in level2.items():
                for categoryEvent, level4 in level3.items():
                    output += "# Family \"%s\" - Category \"%s\"\n" % (familyEvent, categoryEvent)
                    for MsgEvent, i in level4.items():
                        if i == 1:
                            nb = ""
                        else:
                            nb = "%dx " % i
                        output += "- %s%s\n" % (nb, MsgEvent)
                    output += "\n"

    output += "For more details, please visit : %s" % (link)

    # print output
    # print "Taille: %d" % len(output)

    return output
