from artwork import *

class FormattedExceptions(Exception):
    def __init__(self, message):
        super().__init__(self.format_error(message))

    def format_error(self, message):
        return f"{FORE_WHITE}{BG_MAGENTA}[ERROR]{RESET} {FORE_MAGENTA}{message}{RESET}"