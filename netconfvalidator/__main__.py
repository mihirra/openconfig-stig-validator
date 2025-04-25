from .utils import runner
import argparse
import os
import sys

parser = argparse.ArgumentParser(description="Tests network configurations in openconfig format against security requirements.",
                                 epilog="The Directory provided should be in the format specified in the README.md file.")
parser.add_argument("--directory", "-d", default=".")
parser.add_argument("--conf_file", "-c", nargs=1)
res = parser.parse_args()
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if base_dir not in sys.path:
    sys.path.append(base_dir)
run_obj = runner.Runner(res.directory, res.conf_file)
run_obj.run_tests()
