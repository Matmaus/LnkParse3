import json
import os
import unittest
from contextlib import redirect_stdout
from io import StringIO

import LnkParse3

TARGET_DIR = os.path.join(os.path.dirname(__file__), 'samples')
JSON_DIR = os.path.join(os.path.dirname(__file__), 'json')


class TestSamples(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None

    def test_json(self):
        for entry in os.scandir(TARGET_DIR):
            with self.subTest(msg=entry.name):
                with open(entry.path, 'rb') as indata:
                    lnk = LnkParse3.lnk_file(indata)

                mock_stdout = StringIO()
                with redirect_stdout(mock_stdout):
                    lnk.print_json(print_all=True)

                our = json.loads(mock_stdout.getvalue())

                json_path = os.path.join(JSON_DIR, f"{entry.name}.json")
                with open(json_path, 'rb') as fp:
                    their = json.load(fp)

                self.assertDictEqual(our, their)


if __name__ == '__main__':
    unittest.main()
