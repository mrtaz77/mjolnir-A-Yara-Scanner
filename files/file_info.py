import os
import hashlib
import datetime
from util.artwork import *

class FileInfo:
	def __init__(self, file_path):
		self.file_path = file_path
		self.size = os.path.getsize(file_path)
		self.first_bytes = self.get_first_bytes(file_path, 20)
		self.md5 = self.calculate_hash(file_path, hashlib.md5())
		self.sha1 = self.calculate_hash(file_path, hashlib.sha1())
		self.sha256 = self.calculate_hash(file_path, hashlib.sha256())
		self.created = self.get_file_time(file_path, 'created')
		self.modified = self.get_file_time(file_path, 'modified')
		self.accessed = self.get_file_time(file_path, 'accessed')
		self.fore = None
	
	def get_file_path(self):
		return self.file_path

	def get_first_bytes(self, file_path, num_bytes):
		with open(file_path, 'rb') as f:
			return f.read(num_bytes).hex()

	def calculate_hash(self, file_path, hash_algorithm):
		with open(file_path, 'rb') as f:
			while chunk := f.read(8192):
				hash_algorithm.update(chunk)
		return hash_algorithm.hexdigest()

	def setColor(self, fore):
		self.fore = fore

	def get_file_time(self, file_path, time_type):
		stat = os.stat(file_path)
		if time_type == 'created':
			return datetime.datetime.fromtimestamp(stat.st_ctime).ctime()
		elif time_type == 'modified':
			return datetime.datetime.fromtimestamp(stat.st_mtime).ctime()
		elif time_type == 'accessed':
			return datetime.datetime.fromtimestamp(stat.st_atime).ctime()

	def __str__(self):
		return (f"{FORE_WHITE}FILE: {self.fore}{self.file_path}{RESET} "
                f"{FORE_WHITE}SIZE: {self.fore}{self.size}{RESET}\n"
                f"{FORE_WHITE}FIRST_BYTES: {self.fore}{self.first_bytes}{RESET}\n"
                f"{FORE_WHITE}MD5: {self.fore}{self.md5}{RESET}\n"
                f"{FORE_WHITE}SHA1: {self.fore}{self.sha1}{RESET}\n"
                f"{FORE_WHITE}SHA256: {self.fore}{self.sha256}{RESET}\n"
                f"{FORE_WHITE}CREATED: {self.fore}{self.created} {RESET} "
                f"{FORE_WHITE}MODIFIED: {self.fore}{self.modified} {RESET} "
                f"{FORE_WHITE}ACCESSED: {self.fore}{self.accessed}{RESET}")