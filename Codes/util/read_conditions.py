class ReadOnlyConditions:
	def __init__(self, conditions):
		self.conditions = conditions
	
	def __str__(self) -> str:
		out = "Conditions:\n\t"
		for cond in self.conditions:
			if cond in ['and', 'or']:
				out += "\n\t"
			out += " " + cond
		return out