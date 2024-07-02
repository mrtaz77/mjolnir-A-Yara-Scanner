import platform
from datetime import datetime, timezone
import os

import argparse
from artwork import *
from DirManager import DirManager

class Mjolnir:
	def __init__(self, rules_path, files_path):
		self.show_system_info()
		self.dir_manager = DirManager(rules_path, files_path)

	def show_system_info(self):
		print(self.format_system_info(self.get_system_info()))

	def run(self):
		self.show_process_id()
		self.dir_manager.scan()
		self.end_message()

	def end_message(self):
		print(f"{FORE_BLACK}{BG_BLUE}[NOTICE]{RESET} {FORE_BLUE}Mjolnir has competed its service{RESET}"
		f"{FORE_WHITE} TIME: {FORE_BLUE}{self.get_time()}")

	def get_time(self):
		return datetime.now(timezone.utc).strftime("%Y%m%dT%H:%M:%SZ")

	def show_process_id(self):
		print(f"{FORE_BLACK}{BG_GREEN}[INFO]{RESET} {FORE_GREEN}Current process PID: {os.getpid()}{RESET}")

	def get_system_info(self):
		system_info = {
			"SYSTEM": platform.node(),
			"TIME": self.get_time(),
			"PLATFORM": f"{platform.system()} {platform.release()} {platform.version()}",
			"PROC": platform.processor(),
			"ARCH": platform.architecture()[0]
		}
		
		if platform.system() == "Windows":
			system_info["PLATFORM"] += f" {platform.win32_edition()}"
			system_info["PROC"] = f"{platform.machine()} {system_info['PROC']}"
		elif platform.system() == "Linux":
			system_info["PROC"] = f"{platform.machine()} {platform.processor()}"
			system_info["PLATFORM"] += f" {platform.linux_distribution()}"
		elif platform.system() == "Darwin":
			system_info["PLATFORM"] += f" macOS {platform.mac_ver()[0]}"
			system_info["PROC"] = f"{platform.machine()} {system_info['PROC']}"
			
		return system_info

	def format_system_info(self, info):
		return (f"{FORE_BLACK}{BG_BLUE}[NOTICE]{RESET} {FORE_BLUE}Summoning mjolnir{RESET} "
				f"{FORE_WHITE}SYSTEM: {FORE_BLUE}{info['SYSTEM']}{RESET} "
				f"{FORE_WHITE}TIME: {FORE_BLUE}{info['TIME']}{RESET} "
				f"{FORE_WHITE}PLATFORM: {FORE_BLUE}{info['PLATFORM']}{RESET} "
				f"{FORE_WHITE}PROC: {FORE_BLUE}{info['PROC']}{RESET} "
				f"{FORE_WHITE}ARCH: {FORE_BLUE}{info['ARCH']}{RESET}")