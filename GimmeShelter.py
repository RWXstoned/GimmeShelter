import sys,os
import argparse
import psutil
import pefile
import ctypes
import hashlib
from ctypes.wintypes import WORD,DWORD,LPVOID
from ctypes import c_void_p


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
MEM_FREE = 0x10000
MEM_RESERVE = 0x2000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000

PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

class SYSTEM_INFO(ctypes.Structure):
 """https://msdn.microsoft.com/en-us/library/ms724958"""
 class _U(ctypes.Union):
  class _S(ctypes.Structure):
   _fields_ = (('wProcessorArchitecture', WORD),
      ('wReserved', WORD))
  _fields_ = (('dwOemId', DWORD), # obsolete
     ('_s', _S))
  _anonymous_ = ('_s',)
 
 
 if ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulonglong):
  DWORD_PTR = ctypes.c_ulonglong
 elif ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulong):
  DWORD_PTR = ctypes.c_ulong
 
 _fields_ = (('_u', _U),
    ('dwPageSize', DWORD),
    ('lpMinimumApplicationAddress', LPVOID),
    ('lpMaximumApplicationAddress', LPVOID),
    ('dwActiveProcessorMask',   DWORD_PTR),
    ('dwNumberOfProcessors', DWORD),
    ('dwProcessorType',   DWORD),
    ('dwAllocationGranularity', DWORD),
    ('wProcessorLevel', WORD),
    ('wProcessorRevision', WORD))
 _anonymous_ = ('_u',)

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
 """https://msdn.microsoft.com/en-us/library/aa366775"""
 PVOID = LPVOID
 SIZE_T = ctypes.c_size_t
 _fields_ = (('BaseAddress', PVOID),
    ('AllocationBase', PVOID),
    ('AllocationProtect', DWORD),
    ('RegionSize', SIZE_T),
    ('State',   DWORD),
    ('Protect', DWORD),
    ('Type', DWORD))
 
 
def findRWX(p):
  k32 = ctypes.WinDLL('kernel32', use_last_error=True)

  #Get System Info
  LPSYSTEM_INFO = ctypes.POINTER(SYSTEM_INFO)  
  k32.GetSystemInfo.restype = None
  k32.GetSystemInfo.argtypes = (LPSYSTEM_INFO,)
  ReadProcessMemory = k32.ReadProcessMemory 
  sysinfo = SYSTEM_INFO()
  k32.GetSystemInfo(ctypes.byref(sysinfo))
  startAddr=sysinfo.lpMinimumApplicationAddress
  currAddr = sysinfo.lpMinimumApplicationAddress
  endAddr = sysinfo.lpMaximumApplicationAddress
  pageSize = sysinfo.dwPageSize

  p = k32.OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, False, p)
  RWXPrivateRanges = []
  RWXImagesRanges = []
  mbi = MEMORY_BASIC_INFORMATION()
  while currAddr < endAddr:
    ret = k32.VirtualQueryEx(p,c_void_p(currAddr),ctypes.byref(mbi), ctypes.sizeof(mbi))
    if(ret == 0):
      print("Error running VirtualQueryEx")
    if mbi.Protect == PAGE_EXECUTE_READWRITE:
       if mbi.Type == MEM_PRIVATE:
          RWXPrivateRanges.append((currAddr,mbi.RegionSize))
       if mbi.Type == MEM_IMAGE:
          RWXImagesRanges.append((currAddr,mbi.RegionSize))
    currAddr = currAddr + mbi.RegionSize

  ret = k32.CloseHandle(p)
  return RWXPrivateRanges,RWXImagesRanges

def isCurrentUser(n):
    currentUser = os.getlogin()
    if (n == currentUser or currentUser == n.split('\\')[1]):
        return True
    return False

def isOddModule(m):
    normalModules = [
        "c:\\windows\\system32",
        "c:\\windows\\fonts",
        "c:\\windows\\globalization\\sorting\\",
        "c:\\windows\\winsxs\\",
        "c:\\windows\\assembly\\",
        "c:\\windows\\microsoft.net\\",
        "c:\\windows\\syswow64\\",
        "c:\\windows\\systemapps\\"
                        ]
    for path in normalModules:
        if m.startswith(path):
            return False
    return True

def hasWininet(m):
   for x in m:
      if x.endswith("wininet.dll"):
         return True
   return False

def isDotNet(m):
   for x in m:
      if x.endswith("clr.dll") or x.endswith("mscoree.dll"):
         return True
   return False


def hasWinhttp(m):
   for x in m:
      if x.endswith("winhttp.dll"):
         return True
   return False

def isDll(m):
    return m.endswith(".dll")

def getHash(filepath):
   sha256 = hashlib.sha256()
   with open(filepath,"rb") as f:
        for b in iter(lambda: f.read(4096),b""):
            sha256.update(b)
        return sha256.hexdigest()
   
def printProcess(d):
    '''
    If there are interesting things to display for that process, print them.
    If not, pass.
    '''
    if not (d["hasWininet"] or d["hasWinhttp"] or len(d["rwxImgs"])>0 or len(d["rwxPriv"])>0 or len(d["oddModules"])>0 or d["rwxSections"]):
       return
    print("-------------------")
    print(f"{d['name']}\t[{d['pid']}]")
    print(f"  [{d['exe']}]")
    hash = getHash(d["exe"])
    print(f"  Sha256: {hash}")
    print("-------------------")
    if(d["hasSignature"]): print("\t\t (!) Signed")
    if(d["noCFG"]): print("\t\t (!) no CF Guard")
    if(d["isDotNet"]): print("\t\t (!) dotNET ")
    if(d["hasWininet"]): print("\t\t (!) has loaded wininet.dll ")
    if(d["hasWinhttp"]): print("\t\t (!) has loaded winhttp.dll ")
    print("")
    if len(d["oddModules"])>0:
        if(not args.verbose):
           print("\t\t (!) Unusual modules found ")
        else:
            print("\n\t ==== [ Unusual Modules ] ====\n")
            for dll in d["oddModules"]:
                print(f"\t\t {dll}")
                print(f"\t\t\t {getHash(dll)}")

    if(d["rwxSections"]):
        if(not args.verbose):
            print("\t\t (!) RWX Sections found")
        else:
            print("\n\t ==== [ RWX Sections ] ====\n")
            print(d["rwxSections"])
    
    if( len(d["rwxImgs"])>0 ):
       if(not args.verbose):
          print("\t\t (!) RWX Sections in Images found")
       else:
        print("\n\t ==== [ Images with RWX ] ====\n")
        for r in d["rwxImgs"]:
            print(f"\t\t ---> 0x{r[0]:08x}\t{r[1]} bytes")

    if( len(d["rwxPriv"])>0 ):
       if(not args.verbose):
          print("\t\t (!) Private RWX Sections in Images found")
       else:
        print("\n\t ==== [ Private memory pages with RWX ] ====\n")
        for r in d["rwxPriv"]:
            print(f"\t\t ---> 0x{r[0]:08x}\t{r[1]} bytes")

    print("\n")

def scanPE(process):
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000
    pe = pefile.PE(process["exe"], fast_load=True)
    process["noCFG"] = not (pe.OPTIONAL_HEADER.DllCharacteristics >> 14) & 0x1

    rwxSections = []
    for s in pe.sections:
       if (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) and (s.Characteristics & IMAGE_SCN_MEM_READ) and (s.Characteristics & IMAGE_SCN_MEM_WRITE):
            rwxSections.append(s.Name)
    process["rwxSections"] = rwxSections

    pe.parse_data_directories( directories=[
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
    ])
        
    process["hasSignature"] = False 
    for s in pe.__structures__:
        if s.name == "IMAGE_DIRECTORY_ENTRY_SECURITY":
            process["hasSignature"]=(s.VirtualAddress != 0 and s.Size !=0)
        

    pe.close()

def opts(argv):
    p = argparse.ArgumentParser(prog = argv[0],
                                usage = "%(prog)s [options]")

    p.add_argument('-v','--verbose', action='store_true', help='Show details on odd modules and RWX sections found')

    filter = p.add_argument_group("Filtering")
    filter.add_argument('-d','--dotnet', action='store_true', help='Display DotNet processes')
    filter.add_argument('-s','--signed', action='store_true', help='Only show signed processes. WARNING: the validity of signature is NOT checked by this script')
    filter.add_argument('-n','--net-only', action='store_true', help='Only show processes with winhttp or wininet already loaded')

    return p.parse_args()

def main(argv):
    global args 

    print('''
          \t\t\t -*-*- [ GimmeShelter.py ] -*-*- \t\t\t 

 Author: RWXstoned\t rwxstoned/at/proton[.]me 
---
 Find a shelter for your implants !
 Situational awareness Python script which will help you better blend in when trying to identify how and where to run implants.\n
 Review which DLLs are loaded and where; find out what opportunities might be there for module stomping, DLL hijacking, hosting code in RWX sections, etc...
 If an executable or DLL is of interest to you, make note of its SHA256 and review it in a lab...
          
 NOTES:
 - When an executable is marked "Signed", the check is fairly rudimentary and does not actually check the validity of that signature - which would imply running extra-commands and be less stealthy.
 - This is not a privesc tool. Only processes running under the current user are checked.
---
          ''')
    args = opts(argv)

    currentProcesses = []
    pids = psutil.pids()
    for pid in pids:
        p = psutil.Process(pid)
        try:
            u = p.username()
        except psutil.AccessDenied:
            continue
        if isCurrentUser(u):
            currentProcesses.append(p)

    for p in currentProcesses:
        process = {}
        try:
            process["name"] = p.name()
            process["pid"] = p.pid
            process["exe"] = p.exe()
        except psutil.NoSuchProcess:
           continue
        try:
            mmaps = p.memory_maps()
        except psutil.AccessDenied:
            continue
        all_modules = [m.path.lower() for m in mmaps]
        odd_modules = [m for m in all_modules if isOddModule(m)]
        odd_modules_dll = [m for m in odd_modules if isDll(m)]
        process["isDotNet"] = isDotNet(all_modules)

        if(not args.dotnet and process["isDotNet"]):
           continue

        process["hasWininet"] = hasWininet(all_modules)
        process["hasWinhttp"] = hasWinhttp(all_modules)
        if(args.net_only and not (process["hasWininet"] or process["hasWinhttp"])):
           continue

        process["rwxPriv"],process["rwxImgs"] = findRWX(p.pid)
        process["oddModules"] = odd_modules_dll

        scanPE(process)
        if(args.signed and not process["hasSignature"]):
           continue
        printProcess(process)
    
if __name__ == '__main__':
   main(sys.argv)