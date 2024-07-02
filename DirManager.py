import os, sys
from files.file_rules import FileRules
from files.file_info import FileInfo
from util.artwork import *

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
		else:
			print(f"{BG_GREEN}{FORE_BLACK}[INFO]{RESET}{FORE_GREEN} Initializing all YARA rules at once (composed string of all rule files)")
			print(f"{BG_GREEN}{FORE_BLACK}[INFO]{RESET}{FORE_GREEN} Initialized {self.number_of_rules_loaded()} YARA rules")

	def validate_path(self, path):
		if os.listdir(path) == []:
			self.exception(f"Provided path \"{path}\" is empty.")
		if not os.path.exists(path):
			self.exception(f"Path not found: \"{path}\"")

	def load_yara_rules(self, path):
		if os.path.isfile(path):
			if path.endswith('.yar'):
				print(f"{BG_GREEN}{FORE_BLACK}[INFO]{RESET}{FORE_GREEN}Processing YARA rules file \"{self.rules_path}\"{RESET}")
				self.yara_rules.append(FileRules(path))
			else:
				self.exception(f"Invalid file extension for YARA rule: {path}")
		elif os.path.isdir(path):
			print(f"{BG_GREEN}{FORE_BLACK}[INFO]{RESET}{FORE_GREEN} Processing YARA rules folder \"{self.rules_path}\"{RESET}")
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
					
	def number_of_rules_loaded(self):
		sum = 0
		for rule in self.yara_rules:
			sum += rule.numberOfRules()
		return sum

	def scan(self):
		print(f"{BG_GREEN}{FORE_BLACK}[INFO]{RESET} {FORE_GREEN}Scanning path \"{self.files_path}\" ...{RESET}")	
		print(f"{BG_GREEN}{FORE_BLACK}[INFO]{RESET} {FORE_GREEN}Scanning {len(self.files_to_scan)} files...{RESET}")
		for file in self.files_to_scan:
			score = 0
			matched_rules = []
			for rule in self.yara_rules:
				if rule.match_file(file.get_file_path()):
					matched_rules.append(rule)
					score += rule.getScore()
			if score > 0:
				self.generateFileReport(file, matched_rules, score)
		print(f"{BG_BLUE}{FORE_BLACK}[NOTICE]{RESET}{FORE_BLUE} Results: {self.alerts} alerts, {self.warnings} warnings{RESET}")
		self.suggestion()

	def generateFileReport(self, file, matched_rules, score):
		color = self.getContextColor(score)
		file.setColor(color)
		print(file)
		print(f"{FORE_WHITE}Score: {color}{score}{RESET}")
		countOfRulesMatched = 1
		for rule in matched_rules:
			rule.match_report(countOfRulesMatched, color)
			countOfRulesMatched += rule.numberOfRulesMatched()
		
	def suggestion(self):
		if self.alerts > 0:
			print(f"{BG_RED}{FORE_BLACK}[RESULT]{RESET} {FORE_RED}Indicators detected!{RESET}")
		elif self.warnings > 0:
			print(f"{BG_YELLOW}{FORE_BLACK}[RESULT]{RESET} {FORE_YELLOW}Suspicious objects detected!{RESET}")
		else:
			print(f"{BG_GREEN}{FORE_BLACK}[RESULT]{RESET} {FORE_GREEN}SYSTEM SEEMS TO BE CLEAN.{RESET}")

	def getContextColor(self, score):
		if score > 100:
			self.alert()
			return FORE_RED
		if score > 60:
			self.warning()
			return FORE_YELLOW
		return FORE_GREEN

	def alert(self):
		self.alerts += 1
		print(f"{BG_RED}{FORE_BLACK}[ALERT]{RESET}")

	def warning(self):
		self.warnings += 1
		print(f"{BG_YELLOW}{FORE_BLACK}[WARNING]{RESET}")

	def exception(self, message):
		print(BG_MAGENTA + f"[ERROR]" + RESET + FORE_MAGENTA + f" {message}" + RESET)
		sys.exit(1)
