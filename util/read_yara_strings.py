class ReadOnlyStrings:
	def __init__(self, strings):
		self.strings = strings
	
	def __str__(self) -> str:
		out = "Strings:\n"
		for string in self.strings:
			out += "\t" + string['name'] + " = " + self.wrap(string['value'], string['type'])
			if 'modifiers' in string:
				for modifier in string['modifiers']:
					out += " " + modifier
			out += "\n"
		return out

	def wrap(self, value, type):
		if type == "text":
			return "\"" + value + "\""	
		return value