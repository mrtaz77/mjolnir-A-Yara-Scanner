import os, sys
from file_rules import FileRules
from file_info import FileInfo
from artwork import *

class DirManager:
	def __init__(self, rules_path, files_path):
		self.rules_path = os.path.abspath(rules_path)
		self.files_path = os.path.abspath(files_path)
		self.yara_rules = []
		self.files_to_scan = []
		self.warnings = 0
		self.alerts = 0

		self.validate_path(self.rules_path)
		self.validate_path(self.files_path)

		self.load_yara_rules(self.rules_path)
		self.load_files_to_scan(self.files_path)

		if not self.yara_rules:
			self.exception(f"No .yar files found in the rules path \"{self.rules_path}\"")

	def validate_path(self, path):
		if os.listdir(path) == []:
			self.exception(f"Provided path \"{path}\" is empty.")
		if not os.path.exists(path):
			self.exception(f"Path not found: \"{path}\"")

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
		color = self.getContextColor(score)
		file.setColor(color)
		print(file)
		countOfRulesMatched = 1
		for rule in matched_rules:
			rule.match_report(countOfRulesMatched, color)
			countOfRulesMatched += rule.numberOfRulesMatched()

	def getContextColor(self, score):
		if score > 100:
			self.alert()
			return FORE_RED
		if score > 60:
			self.warning()
			return FORE_YELLOW
		return FORE_GREEN, BG_GREEN

	def alert(self):
		self.alerts += 1
		print(f"{BG_RED}{FORE_BLACK}[ALERT]{RESET}")

	def warning(self):
		self.warnings += 1
		print(f"{BG_YELLOW}{FORE_BLACK}[WARNING]{RESET}")

	def exception(self, message):
		print(BG_MAGENTA + f"[ERROR]" + RESET + FORE_MAGENTA + f" {message}" + RESET)
		sys.exit(1)
