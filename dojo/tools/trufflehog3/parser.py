import hashlib
import json

from dojo.models import Finding


class TruffleHog3Parser(object):

    def get_scan_types(self):
        return ["Trufflehog3 Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Trufflehog3 Scan"

    def get_description_for_scan_types(self, scan_type):
        return "JSON Output of Trufflehog."

    def get_findings(self, filename, test):
        data = json.load(filename)

        dupes = dict()

        for json_data in data:
            file = json_data["path"]

            reason = json_data["reason"]
            titleText = "Hard Coded " + reason + " in: " + file

            description = ""
            description = "**Commit:** " + str(json_data.get("commit")).split("\n")[0] + "\n"
            description += "\n```\n" + str(json_data.get("commit")).replace('```', '\\`\\`\\`') + "\n```\n"
            description += "**Commit Hash:** " + str(json_data.get("commitHash")) + "\n"
            description += "**Commit Date:** " + json_data["date"] + "\n"
            description += "**Branch:** " + str(json_data.get("branch")) + "\n"
            description += "**Reason:** " + json_data["reason"] + "\n"
            description += "**Path:** " + file + "\n"

            severity = "High"
            if reason == "High Entropy":
                severity = "Info"
            elif "Oauth" in reason or "AWS" in reason or "Heroku" in reason:
                severity = "Critical"
            elif reason == "Generic Secret":
                severity = "Medium"

            strings_found = ""
            for string in json_data["stringsFound"]:
                strings_found += string + "\n"

            dupe_key = hashlib.md5((file + reason).encode("utf-8")).hexdigest()
            description += "\n**Strings Found:**\n```\n" + strings_found + "\n```\n"

            if dupe_key in dupes:
                finding = dupes[dupe_key]
                finding.description = finding.description + description
                finding.nb_occurences += 1
                dupes[dupe_key] = finding
            else:
                dupes[dupe_key] = True

                finding = Finding(title=titleText,
                                  test=test,
                                  cwe=798,
                                  description=description,
                                  severity=severity,
                                  mitigation="Secrets and passwords should be stored in a secure vault and/or secure storage.",
                                  impact="This weakness can lead to the exposure of resources or functionality to unintended actors, possibly providing attackers with sensitive information or even execute arbitrary code.",
                                  references="N/A",
                                  file_path=file,
                                  line=0,  # setting it to a fake value to activate deduplication
                                  url='N/A',
                                  dynamic_finding=False,
                                  static_finding=True,
                                  nb_occurences=1)

                dupes[dupe_key] = finding

        return list(dupes.values())
