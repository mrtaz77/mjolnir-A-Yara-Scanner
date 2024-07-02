from util.artwork import *

class ReadOnlyMatch:
    
	def __init__(self, matches, color):
		self.matches = matches
		self.color = color

	def __str__(self) -> str:
		if self.matches:
			out = f"{FORE_WHITE}MATCHES:\n{RESET}"
			if self.matches.strings:
				count = 1
				for string in self.matches.strings:
					for instance in string.instances:
						out += f"{FORE_WHITE}#{count})  {RESET}"
						out += f"{self.color}{string.identifier}: {instance.matched_data.decode('utf-8')}{RESET} {FORE_WHITE}OFFSET:LENGTH >> {RESET}{self.color}{instance.offset}:{instance.matched_length}{RESET}"
						if string.is_xor():
							out += f"\n     {FORE_WHITE}KEY: {RESET}{self.color}{instance.xor_key}{RESET} {FORE_WHITE}PLAIN-TEXT: {RESET}{self.color}{instance.plaintext().decode('utf-8')}{RESET}"
						out += "\n"
						count += 1
			return out
		else:
			return f"{FORE_WHITE}No matches found{RESET}"