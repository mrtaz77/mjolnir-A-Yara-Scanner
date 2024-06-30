import yara
import plyara
from util.read_yara_strings import ReadOnlyStrings
from util.read_conditions import ReadOnlyConditions
from util.read_match import ReadOnlyMatch

class FileRules:
	def __init__(self, rulesFilePath=None):
		self.rulesFilePath = rulesFilePath
		self.rules = None
		self.parsed_rules = None
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
		if self.rules is None:
			print("No rules in file; You are not worthy of lifting mjolnir")
			return False

		matches = self.rules.match(file_path)

		if matches:
			print(ReadOnlyMatch(matches))
			return True
		else:
			return False