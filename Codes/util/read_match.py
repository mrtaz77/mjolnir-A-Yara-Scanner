class ReadOnlyMatch:
	def __init__(self, matches):
		self.matches = matches

	def	__str__(self) -> str:
		if self.matches:
			out = "MATCHES:\n"
			for match in self.matches:
				if match.strings:
					count = 1
					for string in match.strings:
						for instance in string.instances:
							out += "#" + str(count) + "\t"
							out += string.identifier + ": " + instance.matched_data.decode('utf-8') + " OFFSET:LENGTH >> " + str(instance.offset) + ":" + str(instance.matched_length)
							if string.is_xor():
								out += "\n\tKEY: " + str(instance.xor_key) + " PLAIN-TEXT: " + instance.plaintext().decode('utf-8')
							out += "\n"
							count += 1
			return out
		else:
			return "No matches found"