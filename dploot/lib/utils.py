from datetime import datetime, timedelta
import logging
import os
import random
import re
import string
from typing import Dict, List


def is_guid(value: str):
    guid = re.compile(
        r"^(\{{0,1}([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})\}{0,1})$"
    )
    return guid.match(value)


def find_guid(value: str):
    guid = re.compile(
        r"(([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12}))"
    )
    return guid.search(value).group()


def find_sha1(value: str):
    guid = re.compile(r"([a-f0-9]{40})")
    return guid.search(value).group()


def is_certificate_guid(value: str):
    guid = re.compile(
        r"^(\{{0,1}([0-9a-fA-F]{32})_([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})\}{0,1})$"
    )
    return guid.match(value)


def is_credfile(value: str):
    guid = re.compile(r"[A-F0-9]{32}")
    return guid.match(value)


def handle_outputdir_option(directory: str) -> str:
    if directory is not None and directory != "":
        if not os.path.exists(directory):
            os.makedirs(directory, 0o744)
        elif not os.path.isdir(directory):
            logging.error("Output Directory exists and is a file, exiting...")
            os.exit(1)
        return directory
    return None


def get_random_chars(size: int = 10) -> str:
    charset = string.ascii_uppercase + string.digits + string.ascii_lowercase
    return "".join(random.choice(charset) for i in range(size))


def datetime_to_time(timestamp_utc) -> str:
    return (datetime(1601, 1, 1) + timedelta(microseconds=timestamp_utc)).strftime(
        "%b %d %Y %H:%M:%S"
    )

def dump_looted_files_to_disk(output_dir, looted_files) -> None:
    for path, file_content in looted_files.items():
        local_filepath = os.path.join(output_dir, path)
        os.makedirs(os.path.dirname(local_filepath), exist_ok=True)
        with open(local_filepath,"wb") as f:
            if file_content is None:
                file_content = b""
            f.write(file_content)

def parse_file_as_list(filename: str) -> List[str]:
    with open(filename) as lines:
        return [line.rstrip("\n") for line in lines]


def parse_file_as_dict(filename: str) -> Dict[str, str]:
    arr = {}
    with open(filename) as lines:
        for line in lines:
            tmp_line = line.rstrip("\n")
            tmp_line = tmp_line.split(":", 1)
            arr[tmp_line[0]] = tmp_line[1]
    return arr

def add_general_args(parser):
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")

    parser.add_argument(
        "-quiet", action="store_true", help="Only output dumped credentials"
    )

    parser.add_argument(
        "-export-dir",
        action="store",
        metavar="DIR",
        help=(
            "Dump looted files to specified directory, regardless they were decrypted"
        ),
    )