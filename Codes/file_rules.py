import yara
import plyara

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