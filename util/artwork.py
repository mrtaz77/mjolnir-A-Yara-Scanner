from colorama import init, Fore, Back, Style

init()

FORE_RED = Fore.LIGHTRED_EX
FORE_GREEN = Fore.LIGHTGREEN_EX
FORE_BLUE = Fore.LIGHTBLUE_EX
FORE_YELLOW = Fore.YELLOW
FORE_WHITE = Fore.WHITE
FORE_BLACK = Fore.BLACK
FORE_MAGENTA = Fore.LIGHTMAGENTA_EX
FORE_CYAN = Fore.CYAN

BG_GREEN = Back.LIGHTGREEN_EX
BG_RED = Back.LIGHTRED_EX
BG_BLUE = Back.LIGHTBLUE_EX
BG_YELLOW = Back.YELLOW
BG_MAGENTA = Back.LIGHTMAGENTA_EX
BG_WHITE = Back.WHITE

RESET = Style.RESET_ALL

artwork = f"""
{Style.BRIGHT}{FORE_WHITE}**********************************************************************{RESET}{FORE_CYAN}
.___  ___.        __    ______    __      .__   __.  __  .______      
|   \/   |       |  |  /  __  \  |  |     |  \ |  | |  | |   _  \     
|  \  /  |       |  | |  |  |  | |  |     |   \|  | |  | |  |_)  |    
|  |\/|  | .--.  |  | |  |  |  | |  |     |  . `  | |  | |      /     
|  |  |  | |  `--'  | |  `--'  | |  `----.|  |\   | |  | |  |\  \----.
|__|  |__|  \______/   \______/  |_______||__| \__| |__| | _| `._____|

{RESET}{Style.BRIGHT}{FORE_WHITE}**********************************************************************
      Y    A    R    A           S    C    A    N    N    E    R{RESET}
"""