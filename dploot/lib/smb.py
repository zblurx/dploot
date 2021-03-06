import sys
import ntpath
import logging
from typing import Any, Dict, List

from dploot.lib.target import Target

from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import RemoteOperations
from impacket.smb3structs import FILE_READ_DATA, FILE_OPEN, FILE_NON_DIRECTORY_FILE, FILE_SHARE_READ

class DPLootSMBConnection:
    def __init__(self, target: Target) -> None:
        self.target = target

        self.smb_session = None
        self.remote_ops = None

    def connect(self) -> None:
        try:
            self.smb_session = SMBConnection(self.target.address,self.target.address)
            if self.target.do_kerberos:
                self.smb_session.kerberosLogin(
                    user=self.target.username,
                    password=self.target.password,
                    domain=self.target.domain,
                    lmhash=self.target.lmhash,
                    nthash=self.target.nthash,
                    aesKey=self.target.aesKey
                    )
            else:
                self.smb_session.login(
                    user=self.target.username,
                    password=self.target.password,
                    domain=self.target.domain,
                    lmhash=self.target.lmhash,
                    nthash=self.target.nthash
                    )
        except Exception as e:
            print(str(e))
            sys.exit(1)
        return self.smb_session

    def remote_list_dir(self, share, path, wildcard=True) -> (Any | None):
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

    def enable_remoteops(self) -> None:
        if self.remote_ops is not None and self.bootkey is not None:
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

    def getFile(self,  *args, **kwargs) -> (Any | None):
        return self.smb_session.getFile(*args, **kwargs)

    def readFile(self, shareName, path, mode = FILE_OPEN, offset = 0, password = None, shareAccessMode = FILE_SHARE_READ) -> bytes:

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
            if (fileSize-offset) < self.smb_session._SMBConnection._Connection['MaxReadSize']:
                # Skip reading 0 bytes files.
                if (fileSize-offset) > 0:
                    data = self.smb_session._SMBConnection.read(treeId, fileId, offset, fileSize-offset)
            else:
                written = 0
                toBeRead = fileSize-offset
                while written < toBeRead:
                    data = self.smb_session._SMBConnection.read(treeId, fileId, offset, self.smb_session._SMBConnection._Connection['MaxReadSize'])
                    written += len(data)
                    offset  += len(data)
        except Exception as e:
            if 'STATUS_OBJECT_PATH_NOT_FOUND' in e.__str__:
                logging.debug(str(e))
            else:
                logging.error(str(e))
        finally:
            if fileId is not None:
                self.smb_session._SMBConnection.close(treeId, fileId)
            self.smb_session.disconnectTree(treeId)
            return data