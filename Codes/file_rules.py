import yara
import plyara
from util.read_yara_strings import ReadOnlyStrings
from util.read_conditions import ReadOnlyConditions
from util.read_match import ReadOnlyMatch
from artwork import *

class FileRules:
	def __init__(self, rulesFilePath=None):
		self.rulesFilePath = rulesFilePath
		self.rules = None
		self.parsed_rules = None
		self.score = 0
		if rulesFilePath is not None:
			self.load_rules(rulesFilePath)

	def load_rules(self, rulesFilePath):
		self.rulesFilePath = rulesFilePath
		self.rules = yara.compile(filepath=rulesFilePath)
		with open(rulesFilePath, 'r') as f:
			rule_content = f.read()
		parser = plyara.Plyara()
		self.parsed_rules = parser.parse_string(rule_content)

	def show(self):
		if self.rules is None:
			print("No rules in file; You are not worthy of lifting mjolnir")
			return
		print(f"Number of rules: {self.numberOfRules()}")
		count = 1
		for rule, parsed_rule in zip(self.rules, self.parsed_rules):
			print(f"Rule #{count}: {rule.identifier}")
			self.showTags(rule)
			self.showMetaData(rule)
			self.showStrings(parsed_rule)
			self.showCondition(parsed_rule)
			count += 1
			print()

	def numberOfRules(self):
		if self.rules is not None:
			return sum(1 for _ in self.rules)
		return 0

	def showTags(self, rule):
		if rule.tags:
			print("Tags:", end="\n\t")
			print(", ".join(rule.tags) + ".")
		else:
			print("Tags: None")

	def showMetaData(self, rule):
		print("Meta:")
		for key, value in rule.meta.items():
			print(f"\t{key}: {value}")

	def showStrings(self, parsed_rule):
		print(ReadOnlyStrings(parsed_rule['strings']))

	def showCondition(self, parsed_rule):
		print(ReadOnlyConditions(parsed_rule['condition_terms']))

	def match_file(self, file_path):
		self.score = 0
		if self.rules is None:
			print("No rules in file; You are not worthy of lifting mjolnir")
			return False

		self.matches = self.rules.match(file_path)
		self.increaseScore(len(self.matches) * 70)
		return self.matches is not None

	def increaseScore(self, score):
		self.score += score

	def match_report(self, initReasonCount, color):
		for match in self.matches:
			print(f"{FORE_WHITE}REASON_{initReasonCount}: {color}Yara Rule {RESET}MATCH: {color}{match.rule} {RESET}SUBSCORE: {color}70{RESET}")
			self.showDescAndAuthor(match.rule, color)
			initReasonCount += 1
			print(ReadOnlyMatch(match, color))

	def numberOfRulesMatched(self):
		return len(self.matches)

	def getScore(self):
		return self.score
	
	def showDescAndAuthor(self, rule, color):
		desc = "Not set"
		author = "-"
		for r in self.rules:
			if r.identifier == rule:
				if 'description' in r.meta:
					desc = r.meta['description']
				if 'author' in r.meta:
					author = r.meta['author']
				break
		print(f"{FORE_WHITE}DESCRIPTION: {color}{desc} {FORE_WHITE}AUTHOR: {color}{author}{RESET}")
