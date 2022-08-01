# VelociraptorHayabusa

1. Use Windows.EVTX.Hayabusa artifact to copy all relevant evtx files from all endpoints.
2. Manually download Results from VR which should give the H.xxx.zip file.
4. Have folder containg both `H.xxxxxx.zip` and `ready4hayabusa.py`. 
3. Run `ready4hayabusa.py`: this unzips/extracts the evtx from H.xxx.zip from all clients into a `results` folder. 
4. Afterwards you run hayabusa against those evtx with: `hayabusa.exe -d ./results/ -r /hayabusa/rules/sigma/ -o ./results.csv`

# Gather EVTX For Hayabusa Artifact
```yml
name: Windows.EVTX.HayaBusa
author: Paddy Cahil
description: |
    Gather evtx logs required for hayabusa to be run.

    NOTE: strings with comma "," requre quotes.


    IocLookupTable csv details: -- https://github.com/Yamato-Security/hayabusa-rules/blob/main/config/channel_abbreviations.txt
      Glob - "Quote" items with { glob } barckets.
      App - Free text description

parameters:
  - name: UploadHits
    description: Upload hits to server.
    type: bool

  - name: IocLookupTable 
    type: csv
    default: |
        Glob,App
        "c:/windows/system32/winevt/logs/DNS Server.evtx",DNS-Svr
        "c:/windows/system32/winevt/logs/Key Management Service.evtx",KeyMgtSvc
        "c:/windows/system32/winevt/logs/Microsoft-ServiceBus-Client.evtx",SvcBusCli
        "c:/windows/system32/winevt/logs/Microsoft-Windows-CodeIntegrity/Operational.evtx",CodeInteg
        "c:/windows/system32/winevt/logs/Microsoft-Windows-LDAP-Client/Debug.evtx",LDAP-Cli
        "c:/windows/system32/winevt/logs/Microsoft-Windows-AppLocker/MSI and Script.evtx",AppLocker
        "c:/windows/system32/winevt/logs/Microsoft-Windows-AppLocker/EXE and DLL.evtx",AppLocker
        "c:/windows/system32/winevt/logs/Microsoft-Windows-AppLocker/Packaged app-Deployment.evtx",AppLocker
        "c:/windows/system32/winevt/logs/Microsoft-Windows-AppLocker/Packaged app-Execution.evtx",AppLocker
        "c:/windows/system32/winevt/logs/Microsoft-Windows-Bits-Client/Operational.evtx",BitsCli
        "c:/windows/system32/winevt/logs/Microsoft-Windows-DHCP-Server/Operational.evtx",DHCP-Svr
        "c:/windows/system32/winevt/logs/Microsoft-Windows-DriverFrameworks-UserMode/Operational.evtx",DvrFmwk
        "c:/windows/system32/winevt/logs/Microsoft-Windows-NTLM/Operational.evtx",NTLM
        "c:/windows/system32/winevt/logs/Microsoft-Windows-Security-Mitigations/KernelMode.evtx",SecMitig
        "c:/windows/system32/winevt/logs/Microsoft-Windows-Security-Mitigations/UserMode.evtx",SecMitig
        "c:/windows/system32/winevt/logs/Microsoft-Windows-SmbClient/Security.evtx",SmbCliSec
        "c:/windows/system32/winevt/logs/Microsoft-Windows-Sysmon/Operational.evtx",Sysmon
        "c:/windows/system32/winevt/logs/Microsoft-Windows-TaskScheduler/Operational.evtx",TaskSch
        "c:/windows/system32/winevt/logs/Microsoft-Windows-TerminalServices-RDPClient/Operational.evtx",RDP-Client
        "c:/windows/system32/winevt/logs/Microsoft-Windows-PrintService/Admin.evtx",PrintAdm
        "c:/windows/system32/winevt/logs/Microsoft-Windows-PrintService/Operational.evtx",PrintOp
        "c:/windows/system32/winevt/logs/Microsoft-Windows-PowerShell/Operational.evtx",PwSh
        "c:/windows/system32/winevt/logs/Microsoft-Windows-Windows Defender/Operational.evtx",Defender
        "c:/windows/system32/winevt/logs/Microsoft-Windows-Windows Firewall With Advanced Security/Firewall.evtx",Firewall
        "c:/windows/system32/winevt/logs/Microsoft-Windows-WinRM/Operational.evtx",WinRM
        "c:/windows/system32/winevt/logs/Microsoft-Windows-WMI-Activity/Operational.evtx",WMI
        "c:/windows/system32/winevt/logs/MSExchange Management.evtx",Exchange
        "c:/windows/system32/winevt/logs/OpenSSH/Operational.evtx",OpenSSH
        "c:/windows/system32/winevt/logs/Security.evtx",Sec
        "c:/windows/system32/winevt/logs/System.evtx",Sys
        "c:/windows/system32/winevt/logs/Windows PowerShell.evtx",PwShClassic

sources:
  - query: |
      -- extract IOCs from lookupTable
      LET hits = SELECT * FROM foreach(
            row=IocLookupTable,
            query={
                SELECT
                    FullPath,
                    Name,
                    Description,
                    timestamp(epoch=Mtime) as Mtime,
                    timestamp(epoch=Atime) as Atime,
                    timestamp(epoch=Ctime) as Ctime,
                    timestamp(epoch=Btime) as Btime,
                    Size,
                    IsLink,IsDir
              
                FROM glob(globs=Glob)
           
            })

      -- upload hits
      LET upload_hits = SELECT *, upload(file=FullPath) FROM hits

      -- output rows
      SELECT * FROM if(condition=UploadHits,
            then= upload_hits,
            else= hits)
```

# ready4hayabusa.py
```python
import os
import zipfile
import glob
import shutil

# Takes VR results and puts all the evtx into one folder

# folder Structure Should be:
# H.xxxxxx.zip
# ready4hayabusa.py 

# Must rename variable zippy 


results_folder = "./results"
unzipped_folder = "./unzipped"

###############################
zippy = "H.xxx.zip"
###############################

def unzipit(infile, unzipped_folder):
    print('unzipping')
    with zipfile.ZipFile(infile,"r") as zip_ref:
        zip_ref.extractall(unzipped_folder)

def make_results_folder(results_folder):
    # check if it exists
    if os.path.exists(results_folder):
        print('removing', results_folder)
        os.rmdir(results_folder)
        # now make it
        os.mkdir(results_folder)
        print('making', results_folder)
    else:
        os.mkdir(results_folder)
        print('making', results_folder)

def get_clients():
    path = "./unzipped/clients/"
    x = os.listdir(path)
    return x


# Make folder for results
make_results_folder(results_folder)

# Unzip results to folder
unzipit(zippy, unzipped_folder)

# Get list of client hostnames
clients = get_clients()


for client in clients:
    print('getting paths')
     # Get list of client name combined with evtx file
    full_paths = glob.iglob(f'./unzipped/clients/{client}/**/*evtx', recursive=True)
    #clients_evtx = [ for x in glob.iglob(f'./unzipped/clients/{client}/**/*evtx', recursive=True)]

    for evtx in full_paths:
        print('moving', os.path.basename(evtx))
        shutil.move(evtx, f'./results/{client}_{os.path.basename(evtx)}')
    # Move to somewhere but renamed- results?
    
print('Now run: hayabusa.exe -d ./results/ -r /hayabusa/rules/sigma/ -o ./results.csv')
```
