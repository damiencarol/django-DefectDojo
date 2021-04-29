import hashlib
import re

from defusedxml.ElementTree import parse

from dojo.models import Endpoint, Finding


class OvalParser(object):
    """OVAL is an information security community effort to standardize how to assess and report upon the machine state of computer systems.
    OVAL includes a language to encode system details, and an assortment of content repositories held throughout the community.
    References:
      * https://oval.mitre.org/
      * https://github.com/OVAL-Community/OVAL
    """

    def get_scan_types(self):
        return ["OVAL Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import Openscap Vulnerability Scan in XML formats."

    def get_findings(self, file, test):
        tree = parse(file)
        # get root of tree.
        root = tree.getroot()
        #namespace = self.get_namespace(root)

        dupes = dict()

        return list(dupes.values())
