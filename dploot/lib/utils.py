from datetime import datetime, timedelta
import logging
import os
import random
import re
import string
from typing import Dict, List


def is_guid(value: str):
	guid = re.compile(r'^(\{{0,1}([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})\}{0,1})$')
	return guid.match(value)

def find_guid(value: str):
	guid = re.compile(r'(([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12}))')
	return guid.search(value).group()

def find_sha1(value: str):
	guid = re.compile(r'([a-f0-9]{40})')
	return guid.search(value).group()

def is_certificate_guid(value: str):
	guid = re.compile(r'^(\{{0,1}([0-9a-fA-F]{32})_([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})\}{0,1})$')
	return guid.match(value)

def is_credfile(value: str):
	guid = re.compile(r'[A-F0-9]{32}')
	return guid.match(value)

def handle_outputdir_option(dir: str) -> str:
	if dir is not None and dir != '':
		if not os.path.exists(dir):
			os.makedirs(dir, 0o744)
		elif not os.path.isdir(dir):
			logging.error("Output Directory exists and is a file, exiting...")
			os.exit(1)
		return dir
	return None

def get_random_chars(size:int = 10) -> str:
	charset = string.ascii_uppercase + string.digits + string.ascii_lowercase
	return ''.join(random.choice(charset) for i in range(size))

def datetime_to_time(timestamp_utc) -> str:
	return (datetime(1601, 1, 1) + timedelta(microseconds=timestamp_utc)).strftime('%b %d %Y %H:%M:%S')

def parse_file_as_list(filename: str) -> List[str]:
	arr = list()
	with open(filename, 'r') as lines:
		for line in lines:
			arr.append(line.rstrip('\n'))
	return arr

def parse_file_as_dict(filename: str) -> Dict[str,str]:
	arr = dict()
	with open(filename, 'r') as lines:
		for line in lines:
			l = line.rstrip('\n')
			l = l.split(':',1)
			arr[l[0]]=l[1]
	return arr