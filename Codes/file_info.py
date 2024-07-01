import os
import hashlib
import datetime

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

    def get_first_bytes(self, file_path, num_bytes):
        with open(file_path, 'rb') as f:
            return f.read(num_bytes).hex()

    def calculate_hash(self, file_path, hash_algorithm):
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_algorithm.update(chunk)
        return hash_algorithm.hexdigest()

    def get_file_time(self, file_path, time_type):
        stat = os.stat(file_path)
        if time_type == 'created':
            return datetime.datetime.fromtimestamp(stat.st_ctime).ctime()
        elif time_type == 'modified':
            return datetime.datetime.fromtimestamp(stat.st_mtime).ctime()
        elif time_type == 'accessed':
            return datetime.datetime.fromtimestamp(stat.st_atime).ctime()

    def __str__(self):
        return (f"FILE: {self.file_path} SIZE: {self.size}\n"
                f"FIRST_BYTES: {self.first_bytes}\n"
                f"MD5: {self.md5}\n"
                f"SHA1: {self.sha1}\n"
                f"SHA256: {self.sha256}\n"
                f"CREATED: {self.created}\n"
                f"MODIFIED: {self.modified}\n"
                f"ACCESSED: {self.accessed}")