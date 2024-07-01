import os
from file_rules import FileRules
from file_info import FileInfo
from artwork import *

class DirManager:
	def __init__(self, rules_path, files_path):
		self.rules_path = rules_path
		self.files_path = files_path
		self.yara_rules = []
		self.files_to_scan = []

		self.validate_path(rules_path)
		self.validate_path(files_path)

		self.load_yara_rules(rules_path)
		self.load_files_to_scan(files_path)

		if not self.yara_rules:
			self.exception("No .yar files found in the rules path.")

	def validate_path(self, path):
		if not path:
			self.exception("Provided path is empty.")
		if not os.path.exists(path):
			self.exception(f"Path not found: {path}")

	def load_yara_rules(self, path):
		if os.path.isfile(path):
			if path.endswith('.yar'):
				self.yara_rules.append(FileRules(path))
			else:
				self.exception(f"Invalid file extension for YARA rule: {path}")
		elif os.path.isdir(path):
			for root, _, files in os.walk(path):
				for file in files:
					if file.endswith('.yar'):
						full_path = os.path.join(root, file)
						self.yara_rules.append(FileRules(full_path))

	def load_files_to_scan(self, path):
		if os.path.isfile(path):
			self.files_to_scan.append(FileInfo(path))
		elif os.path.isdir(path):
			for root, _, files in os.walk(path):
				for file in files:
					full_path = os.path.join(root, file)
					self.files_to_scan.append(FileInfo(full_path))
					
	def scan(self):
		for file in self.files_to_scan:
			score = 0
			matched_rules = []
			for rule in self.yara_rules:
				if rule.match_file(file.get_file_path()):
					matched_rules.append(rule)
					score += rule.getScore()
			if len(matched_rules) > 0:
				self.generateFileReport(file, matched_rules, score)

	def generateFileReport(self, file, matched_rules, score):
		print(file)
		print(f"Score: {score}")
		countOfRulesMatched = 1
		for rule in matched_rules:
			rule.match_report(countOfRulesMatched)
			countOfRulesMatched += rule.numberOfRulesMatched()

	def exception(self, message):
		print(BG_MAGENTA + f"[ERROR]" + RESET + FORE_MAGENTA + f" {message}" + RESET)
