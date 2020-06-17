import volatility.plugins.common as common
import volatility.plugins.registry.registryapi as registryapi
import volatility.utils as utils
import volatility.win32 as win32
import volatility.win32.rawreg as rawreg
import volatility.addrspace as addrspace
from volatility.renderers import TreeGrid

import re
import datetime
import struct
import ntpath




well_known_sid_re = [
  (re.compile(r'S-1-5-[0-9-]+-500$'), 'Administrator'),
  (re.compile(r'S-1-5-[0-9-]+-501$'), 'Guest'),
  (re.compile(r'S-1-5-[0-9-]+-502$'), 'KRBTGT'),
  (re.compile(r'S-1-5-[0-9-]+-512$'), 'Domain Admins'),
  (re.compile(r'S-1-5-[0-9-]+-513$'), 'Domain Users'),
  (re.compile(r'S-1-5-[0-9-]+-514$'), 'Domain Guests'),
  (re.compile(r'S-1-5-[0-9-]+-515$'), 'Domain Computers'),
  (re.compile(r'S-1-5-[0-9-]+-516$'), 'Domain Controllers'),
  (re.compile(r'S-1-5-[0-9-]+-517$'), 'Cert Publishers'),
  (re.compile(r'S-1-5-[0-9-]+-520$'), 'Group Policy Creator Owners'),
  (re.compile(r'S-1-5-[0-9-]+-533$'), 'RAS and IAS Servers'),
  (re.compile(r'S-1-5-5-[0-9]+-[0-9]+'), 'Logon Session'),
  (re.compile(r'S-1-5-21-[0-9-]+-518$'), 'Schema Admins'),
  (re.compile(r'S-1-5-21-[0-9-]+-519$'), 'Enterprise Admins'),
  (re.compile(r'S-1-5-21-[0-9-]+-553$'), 'RAS Servers'),
  (re.compile(r'S-1-5-21-[0-9-]+-498$'), 'Enterprise Read-Only Domain Controllers'),
  (re.compile(r'S-1-5-21-[0-9-]+-521$'), 'Read-Only Domain Controllers'),
  (re.compile(r'S-1-5-21-[0-9-]+-522$'), 'Cloneable Domain Controllers'),
  (re.compile(r'S-1-5-21-[0-9-]+-525$'), 'Protected Users'),
  (re.compile(r'S-1-5-21-[0-9-]+-553$'), 'Remote Access Services (RAS)'),
  (re.compile(r'S-1-5-90-0-[0-9]$'), 'Desktop Window Manager'),
]


well_known_sids = {
  'S-1-0': 'Null Authority',
  'S-1-0-0': 'Nobody',
  'S-1-1': 'World Authority',
  'S-1-1-0': 'Everyone',
  'S-1-2': 'Local Authority',
  'S-1-2-0': 'Local (Users with the ability to log in locally)',
  'S-1-2-1': 'Console Logon (Users who are logged onto the physical console)',
  'S-1-3': 'Creator Authority',
  'S-1-3-0': 'Creator Owner',
  'S-1-3-1': 'Creator Group',
  'S-1-3-2': 'Creator Owner Server',
  'S-1-3-3': 'Creator Group Server',
  'S-1-3-4': 'Owner Rights',
  'S-1-4': 'Non-unique Authority',
  'S-1-5': 'NT Authority',
  'S-1-5-1': 'Dialup',
  'S-1-5-2': 'Network',
  'S-1-5-3': 'Batch',
  'S-1-5-4': 'Interactive',
  'S-1-5-6': 'Service',
  'S-1-5-7': 'Anonymous',
  'S-1-5-8': 'Proxy',
  'S-1-5-9': 'Enterprise Domain Controllers',
  'S-1-5-10': 'Principal Self',
  'S-1-5-11': 'Authenticated Users',
  'S-1-5-12': 'Restricted Code',
  'S-1-5-13': 'Terminal Server Users',
  'S-1-5-14': 'Remote Interactive Logon',
  'S-1-5-15': 'This Organization',
  'S-1-5-17': 'This Organization (Used by the default IIS user)',
  'S-1-5-18': 'Local System',
  'S-1-5-19': 'NT Authority',
  'S-1-5-20': 'NT Authority',
  'S-1-5-32-544': 'Administrators',
  'S-1-5-32-545': 'Users',
  'S-1-5-32-546': 'Guests',
  'S-1-5-32-547': 'Power Users',
  'S-1-5-32-548': 'Account Operators',
  'S-1-5-32-549': 'Server Operators',
  'S-1-5-32-550': 'Print Operators',
  'S-1-5-32-551': 'Backup Operators',
  'S-1-5-32-552': 'Replicators',
  'S-1-5-32-554': 'BUILTIN\\Pre-Windows 2000 Compatible Access',
  'S-1-5-32-555': 'BUILTIN\\Remote Desktop Users',
  'S-1-5-32-556': 'BUILTIN\\Network Configuration Operators',
  'S-1-5-32-557': 'BUILTIN\\Incoming Forest Trust Builders',
  'S-1-5-32-558': 'BUILTIN\\Performance Monitor Users',
  'S-1-5-32-559': 'BUILTIN\\Performance Log Users',
  'S-1-5-32-560': 'BUILTIN\\Windows Authorization Access Group',
  'S-1-5-32-561': 'BUILTIN\\Terminal Server License Servers',
  'S-1-5-32-562': 'BUILTIN\\Distributed COM Users',
  'S-1-5-32-568': 'BUILTIN\\IIS IUSRS',
  'S-1-5-32-569': 'Cryptographic Operators',
  'S-1-5-32-573': 'BUILTIN\\Event Log Readers',
  'S-1-5-32-574': 'BUILTIN\\Certificate Service DCOM Access',
  'S-1-5-33': 'Write Restricted',
  'S-1-5-64-10': 'NTLM Authentication',
  'S-1-5-64-14': 'SChannel Authentication',
  'S-1-5-64-21': 'Digest Authentication',
  'S-1-5-80': 'NT Service',
  'S-1-5-86-1544737700-199408000-2549878335-3519669259-381336952': 'WMI (Local Service)',
  'S-1-5-86-615999462-62705297-2911207457-59056572-3668589837': 'WMI (Network Service)',
  'S-1-5-1000': 'Other Organization',
  'S-1-16-0': 'Untrusted Mandatory Level',
  'S-1-16-4096': 'Low Mandatory Level',
  'S-1-16-8192': 'Medium Mandatory Level',
  'S-1-16-8448': 'Medium Plus Mandatory Level',
  'S-1-16-12288': 'High Mandatory Level',
  'S-1-16-16384': 'System Mandatory Level',
  'S-1-16-20480': 'Protected Process Mandatory Level',
  'S-1-16-28672': 'Secure Process Mandatory Level',
  'S-1-5-21-0-0-0-496': 'Compounded Authentication',
  'S-1-5-21-0-0-0-497': 'Claims Valid',
  'S-1-5-32-575': 'RDS Remote Application Services',
  'S-1-5-32-576': 'RDS Endpoint Servers',
  'S-1-5-32-577': 'RDS Management Servers',
  'S-1-5-32-578': 'Hyper-V Admins',
  'S-1-5-32-579': 'Access Control Assistance Ops',
  'S-1-5-32-580': 'Remote Management Users',
  'S-1-5-65-1': 'This Organization Certificate (Kerberos PAC)',
  'S-1-5-84-0-0-0-0-0': 'Usermode Drivers',
  'S-1-5-113': 'Local Account',
  'S-1-5-114': 'Local Account (Member of Administrators)',
  'S-1-5-1000': 'Other Organization',
  'S-1-15-2-1': 'Application Package Context',
  'S-1-18-1': 'Authentication Authority Asserted Identity',
  'S-1-18-2': 'Service Asserted Identity',
}




class Bam(common.AbstractWindowsCommand):
    """Pulls Bam registry data and displays to user. Borrowed code from getsids for sid resolution"""
    def reg_bin_to_file_time(self, rawtime):
	"""
	https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime
    	
	Pull the first 8 bytes that contain the little endian time representation
    	encode to hex, swap then return as datetime 
    	"""
	
	timedata = "".join(rawtime.split(' ')[0:8])
    	hextime = timedata.decode("hex")
    	unpacked, = struct.unpack('<Q', hextime)
    	self.time = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=unpacked/10.)

    	return self.time


    def lookup_sids(self):
        """
	Get local sids from profilelist
        """
	self.regapi.set_current("hklm")

	profile_key = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
	profile_val = "ProfileImagePath"

	self.localsids = {}

	for subkey in self.regapi.reg_get_all_subkeys(None, key = profile_key):
            sid = str(subkey.Name)
            path = self.regapi.reg_get_value(None, key = "", value = profile_val, given_root = subkey)
            if path:
                path = str(path).replace("\x00", "")
                user = ntpath.basename(path)
                self.localsids[sid] = user

        return self.localsids


    def calculate(self):         
	self.regapi = registryapi.RegistryApi(self._config)

	builds_with_old_location = ['16299', '17134']

	# Get Windows build version
	addr_space = utils.load_as(self._config)
	build = addr_space.profile.metadata.get('build', 0)

	# Choose which location of bam to use in the registry. Builds 16299 and 17134
	# use another path. 
	bam_path = ""
	controlset = self.regapi.reg_get_currentcontrolset() or "ControlSet001"

	if build in builds_with_old_location:
	    bam_path = controlset + "\\Services\\bam\\UserSettings"
	else:
	    bam_path = controlset + "\\Services\\bam\\State\\UserSettings"
	
	bam_key = self.regapi.reg_get_key('system', bam_path)

	# Get all subkeys in UserSettings
	bam_sub_keys = self.regapi.reg_get_all_subkeys('system', bam_path, given_root=bam_key)

	# Get all key values, processing the binary content of the values
	self.data = {}
	for sidkey in bam_sub_keys:
	    sidkey_values = []
	    for key, value in self.regapi.reg_yield_values('system', sidkey, thetype = 'REG_BINARY', given_root = sidkey):
		dat = "\n".join(["{0:<48}".format(h) for o, h, c in utils.Hexdump(value)])
		sidkey_values.append({'key': key, 'time': self.reg_bin_to_file_time(dat)})
		#print sidkey.Name, key, self.reg_bin_to_file_time(dat)
	    self.data[sidkey.Name] = sidkey_values

	return self.data


    def find_sid_re(self, sid_string, sid_re_list):
    	for reg, name in sid_re_list:
            if reg.search(sid_string):
                return name


    def generator(self, data):
        localsids = self.lookup_sids()
	
	user = ""
    	for sid in data:
	    if localsids.get(str(sid)):
		user = localsids.get(str(sid)) 
	    elif well_known_sids.get(str(sid)):
		user = well_known_sids.get(str(sid))
	    else: 
		sid_name_re = self.find_sid_re(str(sid), well_known_sid_re)
		if sid_name_re:
		    user = sid_name_re
		else:
		    user = None
	    
	    for values in self.data[sid]:
                yield (0, [
                    str(sid),
		    str(user),
                    str(values['key']),
                    str(values['time'])
                ])


    def unified_output(self, data):
        return TreeGrid([
            ("SID", str),
	    ("Username", str),
            ("Executable", str),
            ("LastExecutionTime", str)],
            self.generator(self.data))
    
