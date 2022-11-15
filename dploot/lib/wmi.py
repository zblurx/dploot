import logging
import random
import socket
import string
import time

from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL

from dploot.lib.target import Target

class DPLootWmiExec:
    def __init__(self, target:Target=None):
        self.__username = target.username
        self.__password = target.password
        self.__domain = target.domain
        self.__lmhash = target.lmhash
        self.__nthash = target.nthash
        self.__aesKey = target.aesKey
        self.__addr = target.address
        self.__kdcHost = target.kdcHost
        self.__doKerberos = target.do_kerberos

        self.__share = 'C$'
        self.__pwd = str('C:\\')
        self.output = str(time.time())
        self.__win32Process = None

    def run(self, command):
        logging.getLogger("impacket").disabled = True
        dcom = DCOMConnection(self.__addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                              self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
        try:
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices= iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()
            self.__win32Process,_ = iWbemServices.GetObject('Win32_Process')
            self.execute_remote(command)
        except  (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
                logging.debug(str(e))
        dcom.disconnect()

    def execute_remote(self, command):
        self.__win32Process.Create(command, self.__pwd, None)
        
