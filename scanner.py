import argparse
from util.artwork import *
from mjolnir import Mjolnir
import os

def parse_args():
	parser = argparse.ArgumentParser(
		description='A tool for scanning files against YARA rules.',
		formatter_class=argparse.ArgumentDefaultsHelpFormatter
	)

	parser.add_argument(
		'-r', '--rules',
		type=str,
		default=os.getcwd(),
		help='Directory or file containing YARA rules'
	)

	parser.add_argument(
		'-f', '--files',
		type=str,
		default=os.getcwd(),
		help='Directory or file to be scanned'
	)

	return parser.parse_args()


def main():
	args = parse_args()
	rules_dir = args.rules
	files_dir = args.files
	print(artwork)
	mjolnir = Mjolnir(rules_dir, files_dir)
	try:
		mjolnir.run()
	except KeyboardInterrupt:
		print("----------------------------------------------------------------")
		print(f"{FORE_BLACK}{BG_BLUE}[NOTICE]{RESET} {FORE_BLUE}Mjolnir was obstructed by a human; sending it back to valhalla...{RESET}")

if __name__ == '__main__':
	main()