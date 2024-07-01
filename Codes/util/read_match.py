class ReadOnlyMatch:
	def __init__(self, matches):
		self.matches = matches

	def	__str__(self) -> str:
		if self.matches:
			out = "MATCHES:\n"
			if self.matches.strings:
				count = 1
				for string in self.matches.strings:
					for instance in string.instances:
						out += "#" + str(count) + ")  "
						out += string.identifier + ": " + instance.matched_data.decode('utf-8') + " OFFSET:LENGTH >> " + str(instance.offset) + ":" + str(instance.matched_length)
						if string.is_xor():
							out += "\n" + " "*5 + "KEY: " + str(instance.xor_key) + " PLAIN-TEXT: " + instance.plaintext().decode('utf-8')
						out += "\n"
						count += 1
			return out
		else:
			return "No matches found"