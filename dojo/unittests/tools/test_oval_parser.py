from django.test import TestCase
from dojo.models import Test
from dojo.tools.oval.parser import OvalParser


class TestOvalParser(TestCase):

    def test_parse_some_findings(self):
        testfile = open("dojo/unittests/scans/oval/cve.xml")
        parser = OvalParser()
        findings = parser.get_findings(testfile, Test())
        self.assertIsInstance(findings, list)
        self.assertEqual(19, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("X-Frame-Options Header Not Set", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(12, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("http://172.17.0.2:80", endpoint.host)
            endpoint = finding.unsaved_endpoints[1]
            self.assertEqual("http", endpoint.protocol)
            self.assertEqual("172.17.0.2", endpoint.host)
            self.assertEqual('/vulnerabilities/brute/', endpoint.path)
        with self.subTest(i=18):
            finding = findings[18]
            self.assertEqual("Private IP Disclosure", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(4, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
