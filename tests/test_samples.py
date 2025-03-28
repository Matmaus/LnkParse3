import base64
import json
import os
import unittest
import warnings
from contextlib import contextmanager, redirect_stdout
from io import StringIO

import LnkParse3

TARGET_DIR = os.path.join(os.path.dirname(__file__), 'samples')
JSON_DIR = os.path.join(os.path.dirname(__file__), 'json')

@contextmanager
def open_sample(path):
    with open(path, 'rb') as indata:
        yield base64.b64decode(indata.read())

class TestSamples(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        warnings.simplefilter('ignore', category=UserWarning)

    def test_json_print_for_all_samples(self):
        for entry in os.scandir(TARGET_DIR):
            with self.subTest(msg=entry.name):
                with open_sample(entry.path) as indata:
                    lnk = LnkParse3.lnk_file(indata=indata)

                mock_stdout = StringIO()
                with redirect_stdout(mock_stdout):
                    lnk.print_json(print_all=True)

                our = json.loads(mock_stdout.getvalue())

                json_path = os.path.join(JSON_DIR, f"{entry.name}.json")
                with open(json_path, 'rb') as fp:
                    their = json.load(fp)

                self.assertDictEqual(our, their, msg=f'failed on test file {entry.name!r}')

    def test_unwanted_attributes_are_not_printed_if_not_specified(self):
        with open_sample('tests/samples/microsoft_example') as indata:
            lnk = LnkParse3.lnk_file(indata=indata)

        mock_stdout = StringIO()
        with redirect_stdout(mock_stdout):
            lnk.print_json(print_all=False)

        our = json.loads(mock_stdout.getvalue())

        json_path = os.path.join(JSON_DIR, "microsoft_example_not_all_attributes.json")
        with open(json_path, 'rb') as fp:
            their = json.load(fp)

        self.assertDictEqual(our, their)

    def test_readable_with_network_info(self):
        with open_sample('tests/samples/network_info') as indata:
            lnk = LnkParse3.lnk_file(indata=indata)

        mock_stdout = StringIO()
        with redirect_stdout(mock_stdout):
            lnk.print_lnk_file(print_all=True)

        our = mock_stdout.getvalue()

        txt_path = os.path.join(JSON_DIR, "readable_with_network_info.txt")
        with open(txt_path, 'r') as fp:
            their = fp.read()

        self.assertEqual(our, their)

    def test_readable_with_local_info(self):
        with open_sample('tests/samples/sample') as indata:
            lnk = LnkParse3.lnk_file(indata=indata)

        mock_stdout = StringIO()
        with redirect_stdout(mock_stdout):
            lnk.print_lnk_file(print_all=True)

        our = mock_stdout.getvalue()

        txt_path = os.path.join(JSON_DIR, "readable_with_local_info.txt")
        with open(txt_path, 'r') as fp:
            their = fp.read()

        self.assertEqual(our, their)

    def test_print_shortcut_target_json(self):
        with open_sample('tests/samples/microsoft_example') as indata:
            lnk = LnkParse3.lnk_file(indata=indata)

        mock_stdout = StringIO()
        with redirect_stdout(mock_stdout):
            lnk.print_shortcut_target(pjson=True)

        our = json.loads(mock_stdout.getvalue())

        json_path = os.path.join(JSON_DIR, "shortcut_target_only.json")
        with open(json_path, 'rb') as fp:
            their = json.load(fp)

        self.assertDictEqual(our, their)

    def test_print_shortcut_target_readable(self):
        with open_sample('tests/samples/microsoft_example') as indata:
            lnk = LnkParse3.lnk_file(indata=indata)

        mock_stdout = StringIO()
        with redirect_stdout(mock_stdout):
            lnk.print_shortcut_target(pjson=False)

        our = mock_stdout.getvalue()

        txt_path = os.path.join(JSON_DIR, "shortcut_target_only.txt")
        with open(txt_path, 'r') as fp:
            their = fp.read()

        self.assertEqual(our, their)

    def test_print_unknown_target(self):
        with open_sample('tests/samples/unknown_target') as indata:
            lnk = LnkParse3.lnk_file(indata=indata)

        mock_stdout = StringIO()
        with redirect_stdout(mock_stdout):
            lnk.print_lnk_file(print_all=True)

        our = mock_stdout.getvalue()

        txt_path = os.path.join(JSON_DIR, "unknown_target.txt")
        with open(txt_path, 'r') as fp:
            their = fp.read()

        self.assertEqual(our, their)

    def test_print_unknown_block(self):
        with open_sample('tests/samples/unknown_block') as indata:
            lnk = LnkParse3.lnk_file(indata=indata)

        mock_stdout = StringIO()
        with redirect_stdout(mock_stdout):
            lnk.print_lnk_file(print_all=True)

        our = mock_stdout.getvalue()

        txt_path = os.path.join(JSON_DIR, "unknown_block.txt")
        with open(txt_path, 'r') as fp:
            their = fp.read()

        self.assertEqual(our, their)


if __name__ == '__main__':
    unittest.main()
