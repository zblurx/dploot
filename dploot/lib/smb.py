import socket
import sys
import ntpath
import logging
import time
from typing import Any, Dict, List

from dploot.lib.target import Target

from impacket.smbconnection import SMBConnection
from impacket.smb import SMB_DIALECT
from impacket.nmb import NetBIOSTimeout
from impacket.examples.secretsdump import RemoteOperations
from impacket.smb3structs import FILE_READ_DATA, FILE_OPEN, FILE_NON_DIRECTORY_FILE, FILE_SHARE_READ

from dploot.lib.wmi import DPLootWmiExec

class DPLootSMBConnection:
    def __init__(self, target: Target) -> None:
        self.target = target

        self.smb_session = None
        self.remote_ops = None
        self.smbv1 = False

    def create_smbv1_conn(self, kdc=''):
        try:
            self.smb_session = SMBConnection(self.target.address if not kdc else kdc, self.target.address if not kdc else kdc, None, preferredDialect=SMB_DIALECT)
            self.smbv1 = True
        except socket.error as e:
            if str(e).find('Connection reset by peer') != -1:
                logging.debug('SMBv1 might be disabled on {}'.format(self.target.address if not kdc else kdc))
            return False
        except (Exception, NetBIOSTimeout) as e:
            logging.debug('Error creating SMBv1 connection to {}: {}'.format(self.target.address if not kdc else kdc, e))
            return False

        return True

    def create_smbv3_conn(self, kdc=''):
        try:
            self.smb_session = SMBConnection(self.target.address if not kdc else kdc, self.target.address if not kdc else kdc, None)
            self.smbv1 = False
        except socket.error as e:
            if str(e).find('Too many open files') != -1:
                logging.error('SMBv3 connection error on {}: {}'.format(self.target.address if not kdc else kdc, e))
            return False
        except (Exception, NetBIOSTimeout) as e:
            logging.debug('Error creating SMBv3 connection to {}: {}'.format(self.target.address if not kdc else kdc, e))
            return False

        return True

    def create_conn_obj(self, kdc=''):
        if self.create_smbv3_conn(kdc):
            return True
        elif self.create_smbv1_conn(kdc):
            return True

        return False

    def connect(self) -> None:
        try:
            if self.target.do_kerberos:
                logging.debug("Authenticating with %s through Kerberos" % self.target.username)
                # getting hostname
                no_ntlm = False
                self.create_conn_obj()
                try:
                    self.smb_session.login('' , '')
                except Exception as e:
                    if "STATUS_NOT_SUPPORTED" in str(e):
                        no_ntlm = True
                    pass
                hostname = self.smb_session.getServerName() if not no_ntlm else self.target.address
                self.smb_session.close()
                self.target.address = hostname + "." + self.target.domain
                logging.debug("Connecting to %s" % self.target.address)
                self.create_conn_obj()
                self.smb_session.kerberosLogin(
                    user=self.target.username,
                    password=self.target.password,
                    domain=self.target.domain,
                    lmhash=self.target.lmhash,
                    nthash=self.target.nthash,
                    aesKey=self.target.aesKey,
                    kdcHost=self.target.kdcHost,
                    useCache=self.target.use_kcache,
                    )
            else:
                logging.debug("Authenticating with %s through NTLM" % self.target.username)
                logging.debug("Connecting to %s" % self.target.address)
                self.create_conn_obj()
                self.smb_session.login(
                    user=self.target.username,
                    password=self.target.password,
                    domain=self.target.domain,
                    lmhash=self.target.lmhash,
                    nthash=self.target.nthash
                    )
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
                logging.debug(str(e))
            sys.exit(1)
        return self.smb_session

    def remote_list_dir(self, share, path, wildcard=True) -> "Any | None":
        if wildcard:
            path = ntpath.join(path, '*')
        try:
            return self.smb_session.listPath(shareName=share, path=ntpath.normpath(path))
        except :
            return None

    def is_admin(self) -> bool:
        try:
            self.smb_session.connectTree('C$')
            is_admin = True
        except:
            is_admin = False
            pass
        return is_admin

    def listPath(self,  *args, **kwargs) -> Any:
        return self.smb_session.listPath(*args, **kwargs)

    def reconnect(self) -> bool:
        self.smb_session.reconnect()
        if self.remote_ops is not None:
            self.enable_remoteops(force=True)

    def enable_remoteops(self, force=False) -> None:
        logging.getLogger("impacket").disabled = True
        if self.remote_ops is not None and self.bootkey is not None and not force:
            return
        try:
            self.remote_ops  = RemoteOperations(self.smb_session, self.target.do_kerberos, self.target.dc_ip)
            self.remote_ops.enableRegistry()
            self.bootkey = self.remote_ops.getBootKey()
        except Exception as e:
            self.logger.error('RemoteOperations failed: {}'.format(e))

    def listDirs(self, share: str, dirlist: List[str]) -> Dict[str, Any]:
        result = dict()
        for path in dirlist:
            tmp = self.remote_list_dir(share, path=path)
            result[path] = tmp

        return result

    def getFile(self,  *args, **kwargs) -> "Any | None":
        return self.smb_session.getFile(*args, **kwargs)

    def readFile(self, shareName, path, mode = FILE_OPEN, offset = 0, password = None, shareAccessMode = FILE_SHARE_READ, bypass_shared_violation = False) -> bytes:
        # ToDo: Handle situations where share is password protected
        path = path.replace('/', '\\')
        path = ntpath.normpath(path)
        if len(path) > 0 and path[0] == '\\':
            path = path[1:]

        treeId = self.smb_session.connectTree(shareName)
        fileId = None

        data = None

        try:
            fileId = self.smb_session.openFile(treeId, path, FILE_READ_DATA, shareAccessMode, FILE_NON_DIRECTORY_FILE, mode, 0)
            fileInfo = self.smb_session.queryInfo(treeId, fileId)
            fileSize = fileInfo['EndOfFile']
            res = self.smb_session._SMBConnection.getIOCapabilities()
            if (fileSize-offset) < res['MaxReadSize']:
                # Skip reading 0 bytes files.
                if (fileSize-offset) > 0:
                    data = self.smb_session._SMBConnection.read(treeId, fileId, offset, fileSize-offset)
            else:
                written = 0
                toBeRead = fileSize-offset
                while written < toBeRead:
                    data = self.smb_session._SMBConnection.read(treeId, fileId, offset, res['MaxReadSize'])
                    written += len(data)
                    offset  += len(data)
        except Exception as e:
            if 'STATUS_OBJECT_PATH_NOT_FOUND' in str(e):
                pass
            elif 'STATUS_OBJECT_NAME_NOT_FOUND' in str(e):
                pass
            elif bypass_shared_violation and 'STATUS_SHARING_VIOLATION' in str(e):
                wmiexec = DPLootWmiExec(target=self.target)
                command = "cmd.exe /Q /c copy \"C:\\%s\" \"C:\\Windows\\Temp\\%s\"" % (path,wmiexec.output)
                wmiexec.run(command)
                time.sleep(1)
                while True:
                    try:
                        data = self.readFile(shareName=shareName, path=wmiexec.output)
                        break
                    except Exception as e:
                        if str(e).find('STATUS_SHARING_VIOLATION') >=0:
                            # Output not finished, let's wait
                            time.sleep(1)
                            pass
                self.smb_session.deleteFile(shareName, wmiexec.output)
            elif str(e).find('Broken') >= 0:
                logging.debug('Connection broken, trying to recreate it')
                self.reconnect()
                return self.readFile(shareName=shareName, path=path, mode=mode, offset=offset, password=password, shareAccessMode=shareAccessMode, bypass_shared_violation=bypass_shared_violation)
            else:
                logging.debug(str(e))
        finally:
            if fileId is not None:
                self.smb_session._SMBConnection.close(treeId, fileId)
            self.smb_session.disconnectTree(treeId)
            return data