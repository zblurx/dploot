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
    guid = re.compile(r"[A-F0-9a-f]{32}")
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


def parse_entropy(value) -> "bytes | None":
    r"""Normalise a CLI ``--entropy`` value into ``bytes`` (or ``None``).

    CLI arguments arrive as ``str``; passing them straight into the DPAPI
    crypto routines raises ``Object type <class 'str'> cannot be passed to C
    code``. This converts the value to ``bytes`` and interprets backslash
    escape sequences such as ``\\x00`` so entropy with trailing null bytes
    (e.g. ``xT5rZW5qVVbrvpuA\\x00``) can be supplied on the command line.
    """
    if value is None or value == "":
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    try:
        # latin-1 round-trips bytes 0x00-0xFF unchanged; unicode_escape then
        # turns literal sequences like "\x00" into their byte values while
        # leaving already-literal characters intact.
        return value.encode("latin-1").decode("unicode_escape").encode("latin-1")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return value.encode("utf-8", errors="surrogateescape")


def safe_filename(name: str) -> str:
    """Make a string safe to use as a filename component."""
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name) or "key"


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