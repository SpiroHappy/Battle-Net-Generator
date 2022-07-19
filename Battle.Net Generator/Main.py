# Imports
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support.ui import Select
from selenium.webdriver.common.proxy import Proxy, ProxyType
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from uuid import uuid4
from Crypto.Util.Padding import pad, unpad
from colorama import Fore
from pynput import keyboard
from pystyle import Colors, Write, Colorate, Center
from names import get_last_name, get_first_name
from datetime import datetime, date
import os
import sys
import json
import time
import random
import string
import threading
import httpx
import requests
import winreg
import psutil
import subprocess
import json as jsond
import binascii
import platform


class AntiDebug:
    inVM = False

    def __init__(self):
        self.processes = list()

        self.blackListedPrograms = [
            "httpdebuggerui.exe",
            "wireshark.exe",
            "fiddler.exe",
            "regedit.exe",
            "cmd.exe",
            "taskmgr.exe",
            "vboxservice.exe",
            "df5serv.exe",
            "processhacker.exe",
            "vboxtray.exe",
            "vmtoolsd.exe",
            "vmwaretray.exe",
            "ida64.exe",
            "ollydbg.exe",
            "pestudio.exe",
            "vmwareuser",
            "vgauthservice.exe",
            "vmacthlp.exe",
            "x96dbg.exe",
            "vmsrvc.exe",
            "x32dbg.exe",
            "vmusrvc.exe",
            "prl_cc.exe",
            "prl_tools.exe",
            "xenservice.exe",
            "qemu-ga.exe",
            "joeboxcontrol.exe",
            "ksdumperclient.exe",
            "ksdumper.exe",
            "joeboxserver.exe",
        ]



        self.blackListedGPU = [
            "Microsoft Remote Display Adapter",
            "Microsoft Hyper-V Video",
            "Microsoft Basic Display Adapter",
            "VMware SVGA 3D",
            "Standard VGA Graphics Adapter",
            "NVIDIA GeForce 840M",
            "NVIDIA GeForce 9400M",
            "UKBEHH_S",
            "ASPEED Graphics Family(WDDM)",
            "H_EDEUEK",
            "VirtualBox Graphics Adapter",
            "K9SC88UK",
            "Стандартный VGA графический адаптер",
        ]

        threading.Thread(target=self.blockDebuggers).start()
        for func in [
            self.listCheck,
            self.registryCheck,
            self.specsCheck,
            self.dllCheck,
            self.procCheck,
        ]:
            process = threading.Thread(target=func, daemon=True)
            self.processes.append(process)
            process.start()
        for t in self.processes:
            try:
                t.join()
            except RuntimeError:
                continue

    def programExit(self):
        print("Virtual Machine Detected")
        time.sleep(5)
        self.__class__.inVM = True

    def blockDebuggers(self):
        for proc in psutil.process_iter():
            if any(
                procstr in proc.name().lower() for procstr in self.blackListedPrograms
            ):
                try:
                    proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

    def listCheck(self):
        for path in [r"D:\Tools", r"D:\OS2", r"D:\NT3X"]:
            if os.path.exists(path):
                self.programExit()

        myName = os.getlogin()
        for user in self.blackListedUsers:
            if myName == user:
                self.programExit()

        myPCName = os.getenv("COMPUTERNAME")
        for pcName in self.blackListedPCNames:
            if myPCName == pcName:
                self.programExit()

        try:
            myHWID = (
                subprocess.check_output(
                    r"wmic csproduct get uuid", creationflags=0x08000000
                )
                .decode()
                .split("\n")[1]
                .strip()
            )
        except Exception:
            myHWID = ""
        for hwid in self.blackListedHWIDS:
            if myHWID == hwid:
                self.programExit()
        try:
            myIP = httpx.get("https://api64.ipify.org/").text.strip()
        except (
            httpx.ReadError,
            httpx.ReadTimeout,
            httpx.ConnectError,
            httpx.ConnectTimeout,
        ):
            pass
        for ip in self.blackListedIPS:
            if myIP == ip:
                self.programExit()

        try:
            myGPU = (
                subprocess.check_output(
                    r"wmic path win32_VideoController get name",
                    creationflags=0x08000000,
                )
                .decode()
                .strip("Name\n")
                .strip()
            )
        except Exception:
            myGPU = ""
        for gpu in self.blackListedGPU:
            if gpu in myGPU.split("\n"):
                self.programExit()

    def specsCheck(self):
        ram = str(psutil.virtual_memory()[0] / 1024**3).split(".")[0]
        if int(ram) <= 4:
            self.programExit()
        disk = str(psutil.disk_usage("/")[0] / 1024**3).split(".")[0]
        if int(disk) <= 50:
            self.programExit()
        if int(psutil.cpu_count()) <= 1:
            self.programExit()

    def registryCheck(self):
        reg1 = os.system(
            "REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2> nul"
        )
        reg2 = os.system(
            "REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2> nul"
        )
        if reg1 != 1 and reg2 != 1:
            self.programExit()

        handle = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum"
        )
        try:
            reg_val = winreg.QueryValueEx(handle, "0")[0]

            if "VMware" in reg_val or "VBOX" in reg_val:
                self.programExit()
        finally:
            winreg.CloseKey(handle)

    def dllCheck(self):
        vmware_dll = os.path.join(os.environ["SystemRoot"], "System32\\vmGuestLib.dll")
        virtualbox_dll = os.path.join(os.environ["SystemRoot"], "vboxmrxnp.dll")

        if os.path.exists(vmware_dll):
            self.programExit()
        if os.path.exists(virtualbox_dll):
            self.programExit()

    def procCheck(self):
        processes = ["VMwareService.exe", "VMwareTray.exe"]
        for proc in psutil.process_iter():
            for program in processes:
                if proc.name() == program:
                    self.programExit()





with open("config.json", "r") as config:
    license_key = json.load(config)


# Standalone variables
thread_lock = threading.Lock()

account_created = 0


def _time():
    return time.strftime("%H:%M:%S", time.gmtime())


class Fivesim:
    def __init__(self, phone_id) -> None:
        self.phone_id = phone_id
        with open("config.json", "r") as config:
            self.config = json.load(config)

        self.api_key = self.config["sms"]["sms_key"]

    def get_number(self) -> dict:
        try:
            token = self.api_key
            country = str(self.config["sms"]["sms_country"]).lower()
            operator = str(self.config["sms"]["sms_operator"]).lower()
            product = "blizzard"

            headers = {
                "Authorization": "Bearer " + token,
                "Accept": "application/json",
            }

            response = httpx.get(
                "https://5sim.net/v1/user/buy/activation/"
                + country
                + "/"
                + operator
                + "/"
                + product,
                headers=headers,
            ).json()

            return {
                "number": response["phone"],
                "phone_id": response["id"],
                "price": response["price"],
            }

        except Exception as err:
            return {False: err}

    def get_balance(self) -> str:
        token = self.api_key

        headers = {
            "Authorization": "Bearer " + token,
            "Accept": "application/json",
        }

        return str(
            round(
                httpx.get("https://5sim.net/v1/user/profile", headers=headers).json()[
                    "balance"
                ],
                3,
            )
        )

    def finish_order(self) -> None:
        token = self.api_key
        c_id = self.phone_id

        headers = {
            "Authorization": "Bearer " + token,
            "Accept": "application/json",
        }

        httpx.get("https://5sim.net/v1/user/finish/" + str(c_id), headers=headers)

    def cancel_order(self) -> None:
        token = self.api_key
        c_id = self.phone_id

        headers = {
            "Authorization": "Bearer " + token,
            "Accept": "application/json",
        }

        httpx.get("https://5sim.net/v1/user/cancel/" + str(c_id), headers=headers)


class SmsActivate:
    def __init__(self) -> None:
        with open("config.json", "r") as config:
            self.config = json.load(config)

        self.api_key = self.config["sms"]["sms_key"]

    def get_number(self):
        response = httpx.get(
            f'https://api.sms-activate.org/stubs/handler_api.php?api_key={self.api_key}&action=getNumber&service=bz&country={self.config["sms"]["sms_country"]}'
        ).text
        if not (":" in response):
            return {False: response}

        self.phone_id = response.split(":")[1]
        self.number = response.split(":")[2]

        return {"number": self.number, "phone_id": self.phone_id}

    def get_balance(self):
        return str(
            round(
                float(
                    httpx.get(
                        f"https://api.sms-activate.org/stubs/handler_api.php?api_key={self.api_key}&action=getBalance"
                    ).text.split(":")[1]
                ),
                3,
            )
        )

    def get_code(self, phone_id):
        response = httpx.get(
            f"https://api.sms-activate.org/stubs/handler_api.php?api_key={self.api_key}&action=getStatus&id={phone_id}"
        ).text
        if not ("STATUS_OK" in response):
            return False
        return response.split(":")[1]

    def ban(self, phone_id) -> None:
        httpx.get(
            f"https://api.sms-activate.org/stubs/handler_api.php?api_key={self.api_key}&action=setStatus&status=8&id={phone_id}"
        )

    def sent(self, phone_id) -> None:
        httpx.get(
            f"https://api.sms-activate.org/stubs/handler_api.php?api_key={self.api_key}&action=setStatus&status=1&id={phone_id}"
        )

    def done(self, phone_id) -> None:
        httpx.get(
            f"https://api.sms-activate.org/stubs/handler_api.php?api_key={self.api_key}&action=setStatus&status=6&id={phone_id}"
        )


class Email:
    def __init__(self, api_key, domain, email_id) -> None:
        self.api_key = api_key
        self.domain = domain
        self.email_id = email_id

    def get_email(self):
        get_mail = httpx.get(
            f"https://api.kopeechka.store/mailbox-get-email?api=2.0&spa=1&site=account.blizzard.com&sender=Battle.net&mail_type={self.domain}&token={self.api_key}"
        ).json()
        if get_mail["status"] == "OK":
            return dict({"mail": get_mail["mail"], "id": get_mail["id"]})
        else:
            return get_mail["value"]

    def checkEmail(self):
        return httpx.get(
            f"http://api.kopeechka.store/mailbox-get-message?full=1&id={self.email_id}&token={self.api_key}&type=text&api=2.0"
        ).text

    def deleteEmail(self):
        httpx.get(
            "https://api.kopeechka.store/mailbox-cancel?id="
            + self.email_id
            + "&token="
            + self.api_key
        )

    def waitForEmail(self):
        tries = 0
        while tries < 20:
            time.sleep(2)
            value = self.checkEmail()
            if not ("WAIT_LINK" in value):
                return (
                    "https://account.blizzard.com/overview?ticket="
                    + value.split("https://account.blizzard.com/overview?ticket=")[
                        1
                    ].split('"')[0]
                )
        return False


class Generator:
    def __init__(self, proxy) -> None:
        with open("config.json", "r") as config:
            self.config = json.load(config)

        # Object Variables
        self.domains = ["@yahoo.com", "@hotmail.com", "@outlook.com"]
        self.proxy = proxy

        self.useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"
        self.t_o = int(self.config["utils"]["timeout"])

    def sprint(self, message: str) -> None:
        thread_lock.acquire()
        sys.stdout.write(message + "\n" + Fore.RESET)
        thread_lock.release()

    # Closes all browsers if f9 is clicked
    def check_keys(self):
        def on_release(key):
            key_pressed = str(key).replace("'", "")
            if key_pressed == "Key.f9":

                if hasattr(self, "Activate"):
                    if not self.Activate:
                        Fivesim(self.phone_id).cancel_order()
                    else:
                        SmsActivate().ban(self.phone_id)

                self.driver.quit()
                thread_lock.acquire()
                sys.stdout.write(
                    f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.YELLOW}/{Fore.RESET}] {Fore.RED}User requested to close all browsers."
                    + "\n"
                    + Fore.RESET
                )
                time.sleep(5)
                os._exit(1)

        with keyboard.Listener(on_release=on_release) as listener:
            listener.join()

    def get_dob(self) -> str:
        return str(
            "{:02d}".format(random.randint(1, 12))
            + "{:02d}".format(random.randint(1, 28))
            + str(random.randint(1990, 2002))
        )

    def __init_driver__(self) -> None:
        if bool(self.config["utils"]["verbose"]):
            self.sprint(
                f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.GREEN}+{Fore.RESET}] {Fore.CYAN}Spoofing Webdriver"
            )
            self.sprint(
                f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.GREEN}+{Fore.RESET}] {Fore.CYAN}Proxy: {Fore.LIGHTMAGENTA_EX}{self.proxy}"
            )

        ser = Service(f"{os.getcwd()}\chromedriver.exe")
        self.proxy_server = self.proxy

        if not self.proxy_server:
            capabilities = None

        else:
            proxy = Proxy()
            proxy.proxy_type = ProxyType.MANUAL
            proxy.http_proxy = self.proxy_server
            proxy.ssl_proxy = self.proxy_server
            capabilities = webdriver.DesiredCapabilities.CHROME
            proxy.add_to_capabilities(capabilities)

        # Spoofing to not get detected
        options = Options()

        options.add_experimental_option(
            "excludeSwitches",
            [
                "enable-logging",
                "enable-automation",
                "ignore-certificate-errors",
                "safebrowsing-disable-download-protection",
                "safebrowsing-disable-auto-update",
                "disable-client-side-phishing-detection",
            ],
        )

        options.add_argument("--lang=en")
        options.add_argument("--log-level=3")
        options.add_argument("--incognito")
        options.add_argument("--no-sandbox")
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--ignore-ssl-errors")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--profile-directory=Null")
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument("--start-maximized")
        options.add_argument(f"--user-agent={self.useragent}")

        if bool(self.config["utils"]["headless"]):
            options.add_argument("--headless")
            options.add_argument("--disable-gpu")

        self.driver = webdriver.Chrome(
            service=ser, desired_capabilities=capabilities, options=options
        )

        self.driver.set_window_size(500, 570)

        self.driver.execute_cdp_cmd(
            "Network.setUserAgentOverride", {"userAgent": self.useragent}
        )

        self.driver.execute_cdp_cmd(
            "Page.addScriptToEvaluateOnNewDocument",
            {
                "source": """
            Object.defineProperty(navigator, 'deviceMemory', {
            get: () => 99
            })
        """
            },
        )

        self.driver.execute_cdp_cmd(
            "Page.addScriptToEvaluateOnNewDocument",
            {
                "source": """
                Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined
                })
            """
            },
        )

    def resend_sms(self) -> None:
        while self.sms_code is True:
            self.driver.execute_script(
                """document.querySelector('#resend-sms-verification').click();"""
            )

    def get_sms_code(self) -> None:
        self.sms_code = True
        threading.Thread(target=self.resend_sms).start()

        if not self.Activate:
            headers = {
                "Authorization": "Bearer " + self.config["sms"]["sms_key"],
                "Accept": "application/json",
            }

            tries = 0
            while tries < int(self.config["utils"]["timeout"]) // 2:
                response = httpx.get(
                    "https://5sim.net/v1/user/check/" + str(self.phone_id),
                    headers=headers,
                ).json()
                if response["status"] == "RECEIVED":
                    if response["sms"]:
                        self.sms_code = response["sms"][0]["code"]
                        Fivesim(self.phone_id).finish_order()
                        return
                else:

                    time.sleep(2)

                    tries += 1

            self.sms_code = None
            return

        else:
            tries = 0

            SmsActivate().sent(self.phone_id)

            while tries < int(self.config["utils"]["timeout"]) // 2:
                time.sleep(2)

                res = SmsActivate().get_code(self.phone_id)

                if not (res is False):
                    SmsActivate().done(self.phone_id)
                    self.sms_code = res
                    return

                tries += 1

            SmsActivate().ban(self.phone_id)

            self.sms_code = None
            return

    def solve_captcha(self):
        cap_service = str(self.config["captcha"]["captcha_service"]).lower()
        cap_key = self.config["captcha"]["cap_key"]

        if "best" in cap_service:
            for _ in range(3):
                create_task = httpx.post(
                    "https://bcsapi.xyz/api/captcha/funcaptcha",
                    json={
                        "page_url": "https://account.battle.net/creation/flow/creation-full",
                        "s_url": "https://blizzard-api.arkoselabs.com",
                        "site_key": "E8A75615-1CBA-5DFF-8032-D16BCF234E10",
                        "access_token": cap_key,
                    },
                ).json()

                task_id = create_task["id"]

                while True:
                    get_result = httpx.get(
                        f"https://bcsapi.xyz/api/captcha/{task_id}?access_token={cap_key}"
                    ).json()
                    try:
                        if get_result["status"] != "completed":
                            pass
                        else:
                            self.captcha_token = get_result["solution"]
                            return
                    except KeyError:
                        if bool(self.config["utils"]["verbose"]):
                            self.sprint(
                                f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.RED}-{Fore.RESET}] {Fore.CYAN}Could not solve captcha, trying again"
                            )
                        break

            if bool(self.config["utils"]["verbose"]):
                self.sprint(
                    f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.RED}-{Fore.RESET}] {Fore.CYAN}Could not solve captcha, ending thread"
                )

            self.captcha_token = None

            return

        elif "monster" in cap_service:
            for _ in range(3):
                if self.proxy_server:
                    create_task = httpx.post(
                        "https://api.capmonster.cloud/createTask",
                        json={
                            "clientKey": cap_key,
                            "task": {
                                "type": "FunCaptchaTask",
                                "websiteURL": "https://account.battle.net/creation/flow/creation-full",
                                "websitePublicKey": "E8A75615-1CBA-5DFF-8032-D16BCF234E10",
                                "proxyType": "http",
                                "proxyAddress": str(self.proxy_server).split(":")[0],
                                "proxyPort": int(str(self.proxy_server).split(":")[1]),
                                "userAgent": self.useragent,
                            },
                        },
                    ).json()
                else:
                    create_task = httpx.post(
                        "https://api.capmonster.cloud/createTask",
                        json={
                            "clientKey": cap_key,
                            "task": {
                                "type": "FunCaptchaTaskProxyless",
                                "websiteURL": "https://account.battle.net/creation/flow/creation-full",
                                "websitePublicKey": "E8A75615-1CBA-5DFF-8032-D16BCF234E10",
                            },
                        },
                    ).json()

                if create_task["errorId"] != 0:
                    if bool(self.config["utils"]["verbose"]):
                        self.sprint(
                            f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.RED}-{Fore.RESET}] {Fore.CYAN}Could not create captcha task, error code: {create_task['errorId']}, ending thread"
                        )

                    self.captcha_token = None

                    return

                task_id = create_task["taskId"]

                for _ in range(120):
                    try:
                        get_result = httpx.post(
                            "https://api.capmonster.cloud/getTaskResult",
                            json={"clientKey": cap_key, "taskId": task_id},
                        ).json()

                        if get_result["status"] == "ready":
                            self.captcha_token = get_result["solution"]["text"]
                            return

                        elif get_result["errorId"] != 0:
                            if bool(self.config["utils"]["verbose"]):
                                self.sprint(
                                    f"""
                                    [{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.RED}-{Fore.RESET}] {Fore.CYAN}Could not get captcha token, error code: {create_task['errorId']}, trying again
                                    """
                                )

                            break

                        else:
                            time.sleep(2)

                    except:
                        if bool(self.config["utils"]["verbose"]):
                            self.sprint(
                                f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.RED}-{Fore.RESET}] {Fore.CYAN}Could not solve captcha, ending thread"
                            )

                        self.captcha_token = None

                        return

            if bool(self.config["utils"]["verbose"]):
                self.sprint(
                    f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.RED}-{Fore.RESET}] {Fore.CYAN}Could not solve captcha, ending thread"
                )

            self.captcha_token = None

            return

        else:
            self.sprint(
                f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.RED}-{Fore.RESET}] {Fore.CYAN}That captcha service is not supported, ending program"
            )

            time.sleep(5)

            os._exit(1)

    def sumbit_captcha_token(self) -> bool:
        for _ in range(3):
            self.solve_captcha()
            if self.captcha_token is None:
                continue

            self.driver.execute_script(
                f"""
                document.querySelector('#capture-arkose').value = "{self.captcha_token}";
                document.querySelector('#flow-form-submit');
                document.querySelector('#capture-arkose').click();
                document.querySelector('#flow-form').submit();
            """
            )

            try:
                WebDriverWait(self.driver, 5).until(
                    EC.presence_of_element_located(
                        (
                            By.XPATH,
                            "//input[@id='capture-first-name']",
                        )
                    )
                )

                return True

            except TimeoutException:
                if bool(self.config["utils"]["verbose"]):
                    self.sprint(
                        f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.RED}-{Fore.RESET}] {Fore.CYAN}Captcha Token Invalid, getting another one"
                    )
                continue

        return False

    def fill_forms(self) -> bool:
        self.driver.get("https://us.account.battle.net/creation/flow/creation-full")
        
        try:
            print('p')

        except WebDriverException:
            if bool(self.config["utils"]["verbose"]):
                self.sprint(
                    f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.RED}-{Fore.RESET}] {Fore.CYAN}Host timed out, ending thread"
                )
            return False

        except Exception as err:
            if bool(self.config["utils"]["verbose"]):
                self.sprint(
                    f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.RED}-{Fore.RESET}] {Fore.CYAN}Unknown Error: {err}, ending thread"
                )
            return False

        WebDriverWait(self.driver, 40).until(
            EC.presence_of_element_located(
                (
                    By.XPATH,
                    "//select[@id='capture-country']",
                )
            )
        )

        if "Accept cookies" in self.driver.page_source:
            cookies = self.driver.find_element(
                By.XPATH, "/html/body/div[1]/div[2]/div[4]/div[2]/div/button"
            )
            self.driver.execute_script("arguments[0].click();", cookies)

        self.driver.find_element(By.ID, "dob-field-inactive").click()
        self.driver.find_element(By.CLASS_NAME, "step__input--date--mm").send_keys(
            self.get_dob()
        )

        if bool(self.config["utils"]["verbose"]):
            self.sprint(
                f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.GREEN}+{Fore.RESET}] {Fore.CYAN}DOB Set"
            )

        if not self.config["captcha"]["use_captcha"]:
            self.driver.execute_script(
                """
                document.getElementById("flow-form-submit-btn").click();
            """
            )

        Select(
            self.driver.find_element(By.XPATH, "//select[@id='capture-country']")
        ).select_by_visible_text(
            str(self.config["account_settings"]["account_country"])
        )

        if bool(self.config["utils"]["verbose"]):
            self.sprint(
                f'[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.GREEN}+{Fore.RESET}] {Fore.CYAN}Country Set: {Fore.LIGHTMAGENTA_EX}{self.config["account_settings"]["account_country"]}'
            )

        if bool(self.config["captcha"]["use_captcha"]) and bool(
            self.config["utils"]["verbose"]
        ):
            self.sprint(
                f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.YELLOW}/{Fore.RESET}] {Fore.CYAN}Solving Captcha"
            )

        if bool(self.config["captcha"]["use_captcha"]):
            if not self.sumbit_captcha_token():
                if bool(self.config["utils"]["verbose"]):
                    self.sprint(
                        f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.RED}-{Fore.RESET}] {Fore.CYAN}Could not get valid captcha token, ending thread"
                    )
                self.driver.quit()
                return False
        else:
            self.driver.execute_script(
                """
                document.getElementById("flow-form-submit-btn").click();
            """
            )

            if bool(self.config["utils"]["verbose"]):
                self.sprint(
                    f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.YELLOW}/{Fore.RESET}] {Fore.CYAN}Waiting for user to solve captcha"
                )

            try:
                WebDriverWait(self.driver, 50000).until(
                    EC.presence_of_element_located(
                        (
                            By.XPATH,
                            "//input[@id='capture-last-name']",
                        )
                    )
                )
                if bool(self.config["utils"]["verbose"]):
                    self.sprint(
                        f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.GREEN}+{Fore.RESET}] {Fore.CYAN}User Solved Captcha"
                    )

            except TimeoutException:
                if bool(self.config["utils"]["verbose"]):
                    self.sprint(
                        f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.RED}-{Fore.RESET}] {Fore.CYAN}Host Timed Out, ending thread"
                    )
                return False

        if bool(self.config["utils"]["verbose"]) and bool(
            self.config["captcha"]["use_captcha"]
        ):
            self.sprint(
                f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.GREEN}+{Fore.RESET}] {Fore.CYAN}Solved Captcha"
            )

        fname, lname = get_first_name(), get_last_name()

        self.driver.find_element(
            By.XPATH, "//input[@id='capture-first-name']"
        ).send_keys(fname)
        self.driver.find_element(
            By.XPATH, "//input[@id='capture-last-name']"
        ).send_keys(lname)

        if bool(self.config["utils"]["verbose"]):
            self.sprint(
                f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.GREEN}+{Fore.RESET}] {Fore.CYAN}Name: {Fore.LIGHTMAGENTA_EX}{fname} {lname}"
            )

        self.driver.find_element(By.CSS_SELECTOR, "#flow-form-submit-btn").click()

        WebDriverWait(self.driver, self.t_o).until(
            EC.presence_of_element_located(
                (
                    By.XPATH,
                    "//input[@id='capture-email']",
                )
            )
        )

        if not self.config["email"]["email_verification"]:
            self.email = "".join(
                random.choice(string.ascii_letters) for _ in range(8)
            ) + random.choice(self.domains)
        else:
            get_email = Email(
                self.config["email"]["email_key"],
                self.config["email"]["email_domain"],
                None,
            ).get_email()

            if not (isinstance(get_email, dict)):
                if bool(self.config["utils"]["verbose"]):
                    self.sprint(
                        f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.RED}-{Fore.RESET}] {Fore.CYAN}Could not get email, error: {Fore.LIGHTMAGENTA_EX}{get_email}"
                    )
                    time.sleep(5)
                return False
            else:
                self.email, self.email_id = get_email["mail"], get_email["id"]

        self.driver.find_element(By.XPATH, "//input[@id='capture-email']").send_keys(
            self.email
        )

        if bool(self.config["utils"]["verbose"]):
            self.sprint(
                f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.GREEN}+{Fore.RESET}] {Fore.CYAN}Email: {Fore.LIGHTMAGENTA_EX}{self.email}"
            )

        if self.config["sms"]["phone_verification"]:
            for _ in range(2):
                if "activate" in str(config["sms"]["sms_service"]).lower():
                    self.Activate = True
                else:
                    self.Activate = False

                for _ in range(5):
                    if not self.Activate:
                        get_number = Fivesim(None).get_number()

                        if str("false") in str(get_number).lower():
                            if bool(self.config["utils"]["verbose"]):
                                self.sprint(
                                    f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.RED}-{Fore.RESET}] {Fore.CYAN}Could not get a number, error: {get_number[False]}, ending thread"
                                )
                            self.driver.quit()
                            return False
                    else:
                        get_number = SmsActivate().get_number()

                        if str("false") in str(get_number).lower():
                            if bool(self.config["utils"]["verbose"]):
                                self.sprint(
                                    f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.RED}-{Fore.RESET}] {Fore.CYAN}Could not get a number, error: {get_number[False]}, ending thread"
                                )
                            self.driver.quit()
                            return False

                    if not self.Activate:
                        self.number, self.phone_id, self.phone_price = (
                            get_number["number"],
                            get_number["phone_id"],
                            get_number["price"],
                        )
                    else:
                        self.number, self.phone_id, self.phone_price = (
                            get_number["number"],
                            get_number["phone_id"],
                            "Undefined",
                        )

                    self.driver.find_element(
                        By.XPATH, "//input[@id='capture-phone-number']"
                    ).send_keys(self.number)

                    if bool(self.config["utils"]["verbose"]):
                        self.sprint(
                            f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.GREEN}+{Fore.RESET}] {Fore.CYAN}Phone Number: {Fore.LIGHTMAGENTA_EX}{self.number} {Fore.LIGHTWHITE_EX}| {Fore.CYAN}Phone Price: {Fore.LIGHTMAGENTA_EX}₽{self.phone_price}"
                        )

                    self.driver.find_element(
                        By.CSS_SELECTOR, "#flow-form-submit-btn"
                    ).click()

                    try:
                        WebDriverWait(self.driver, 4).until(
                            EC.presence_of_element_located(
                                (
                                    By.XPATH,
                                    "//form[@id='flow-form']//li[1]",
                                )
                            )
                        )

                        if bool(self.config["utils"]["verbose"]):
                            self.sprint(
                                f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.RED}-{Fore.RESET}] {Fore.CYAN}Invalid Phone Number, getting a new one"
                            )

                        if not self.Activate:
                            Fivesim(self.phone_id).cancel_order()
                        else:
                            SmsActivate().ban(self.phone_id)

                        self.driver.find_element(
                            By.XPATH, "//input[@id='capture-phone-number']"
                        ).clear()

                        continue

                    except:
                        try:
                            WebDriverWait(self.driver, 20).until(
                                EC.presence_of_element_located(
                                    (
                                        By.ID,
                                        "field-0",
                                    )
                                )
                            )
                            break

                        except TimeoutException:
                            if bool(self.config["utils"]["verbose"]):
                                self.sprint(
                                    f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.RED}-{Fore.RESET}] {Fore.CYAN}Host timed out, ending thread"
                                )
                            return False

                try:
                    WebDriverWait(self.driver, 20).until(
                        EC.presence_of_element_located(
                            (
                                By.ID,
                                "field-0",
                            )
                        )
                    )
                except:
                    if bool(self.config["utils"]["verbose"]):
                        self.sprint(
                            f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.RED}-{Fore.RESET}] {Fore.CYAN}Could not get a valid number, ending thread"
                        )

                    self.driver.quit()
                    return False

                self.get_sms_code()

                if not (self.sms_code is None):
                    if bool(self.config["utils"]["verbose"]):
                        self.sprint(
                            f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.GREEN}+{Fore.RESET}] {Fore.CYAN}Sms Code: {Fore.LIGHTMAGENTA_EX}{self.sms_code}"
                        )

                    self.driver.find_element(By.ID, "field-0").send_keys(self.sms_code)

                    break

                else:
                    self.driver.execute_script(
                        """
                        document.querySelector("#flow-button-back").click();
                    """
                    )

                    WebDriverWait(self.driver, self.t_o).until(
                        EC.presence_of_element_located(
                            (
                                By.XPATH,
                                "//input[@id='capture-phone-number']",
                            )
                        )
                    )

                    self.driver.find_element(
                        By.XPATH, "//input[@id='capture-phone-number']"
                    ).clear()

                    time.sleep(2)
                    continue

        if (
            not self.sms_code
            and self.driver.find_element(
                By.XPATH, "//input[@id='capture-phone-number']"
            ).is_displayed()
        ):
            if bool(self.config["utils"]["verbose"]):
                self.sprint(
                    f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.RED}-{Fore.RESET}] {Fore.CYAN}Could not get sms code, ending thread"
                )

            time.sleep(2)

            self.driver.quit()

        time.sleep(2)
        
        self.driver.execute_script('''
            document.querySelector("#flow-form-submit-btn").click();
        ''')

        WebDriverWait(self.driver, self.t_o).until(
            EC.presence_of_element_located(
                (
                    By.XPATH,
                    "//div[@id='legal-checkboxes']//label",
                )
            )
        )

        self.driver.find_element(
            By.XPATH,
            "//div[@id='legal-checkboxes']//label[@class='step__field--label step__form__block']",
        ).click()
        self.driver.find_element(By.ID, "flow-form-submit-btn").click()

        if bool(self.config["utils"]["verbose"]):
            self.sprint(
                f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.GREEN}+{Fore.RESET}] {Fore.CYAN}Agreed to Tos"
            )

        WebDriverWait(self.driver, self.t_o).until(
            EC.presence_of_element_located(
                (
                    By.XPATH,
                    "//input[@id='capture-password']",
                )
            )
        )

        if len(self.config["account_settings"]["custom_password"]) <= 0:
            self.password = "".join(
                random.choice(string.ascii_letters + string.digits) for _ in range(12)
            )
        else:
            self.password = self.config["account_settings"]["custom_password"]

        self.driver.find_element(By.XPATH, "//input[@id='capture-password']").send_keys(
            self.password
        )

        self.driver.find_element(By.CSS_SELECTOR, "#flow-form-submit-btn").click()

        if bool(self.config["utils"]["verbose"]):
            self.sprint(
                f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.GREEN}+{Fore.RESET}] {Fore.CYAN}Password Set To: {Fore.LIGHTMAGENTA_EX}{self.password}"
            )

        WebDriverWait(self.driver, self.t_o).until(
            EC.presence_of_element_located(
                (
                    By.XPATH,
                    "//input[@id='capture-battletag']",
                )
            )
        )

        if self.config["account_settings"]["custom_name"] in ["", False]:
            acc_username = self.driver.find_element(
                By.XPATH, "//input[@id='capture-battletag']"
            ).get_attribute("value")
            if bool(self.config["utils"]["verbose"]):
                self.sprint(
                    f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.GREEN}+{Fore.RESET}] {Fore.CYAN}Preset Name: {Fore.LIGHTMAGENTA_EX}{acc_username}"
                )
            self.driver.find_element(By.CSS_SELECTOR, "#flow-form-submit-btn").click()

        else:
            self.driver.find_element(
                By.XPATH, "//input[@id='capture-battletag']"
            ).clear()
            self.driver.find_element(
                By.XPATH, "//input[@id='capture-battletag']"
            ).send_keys(str(self.config["account_settings"]["custom_name"]))
            self.driver.find_element(By.CSS_SELECTOR, "#flow-form-submit-btn").click()

            acc_username = self.config["account_settings"]["custom_name"]

            if bool(self.config["utils"]["verbose"]):
                self.sprint(
                    f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.GREEN}+{Fore.RESET}] {Fore.CYAN}Username Set To: {Fore.LIGHTMAGENTA_EX}{acc_username}"
                )

        WebDriverWait(self.driver, self.t_o).until(
            EC.presence_of_element_located(
                (
                    By.XPATH,
                    "//p[normalize-space()='The following Battle.net Account has been created:']",
                )
            )
        )

        self.driver.implicitly_wait(2)

        self.driver.find_element(
            By.XPATH, "//a[normalize-space()='Account Settings']"
        ).click()

        self.driver.switch_to.window(self.driver.window_handles[1])

        try:
            WebDriverWait(self.driver, 5).until(
                EC.presence_of_element_located(
                    (
                        By.CSS_SELECTOR,
                        "#submit",
                    )
                )
            )

            self.driver.implicitly_wait(2)

            self.driver.execute_script(
                """
                document.querySelector("#submit").click();
            """
            )
        except:
            pass

        WebDriverWait(self.driver, self.t_o).until(
            EC.presence_of_element_located(
                (
                    By.XPATH,
                    "//h1[normalize-space()='Account Overview']",
                )
            )
        )

        time.sleep(3)
        self.driver.switch_to.window(self.driver.window_handles[0])

        if self.config["email"]["email_verification"]:
            self.driver.get("https://account.battle.net/details#email")
            WebDriverWait(self.driver, self.t_o).until(
                EC.presence_of_element_located(
                    (By.XPATH, '//*[@id="email-card"]/div[1]/div/div[1]/h3')
                )
            )
            for _ in range(2):
                verify_email = Email(
                    self.config["email"]["email_key"], None, self.email_id
                ).waitForEmail()
                if not verify_email:
                    self.driver.execute_script(
                        """
                        document.querySelector("#email-card > div.card-subtitle > div > div > div:nth-child(2) > span > span > span > a").click();
                    """
                    )
                    continue
                else:
                    self.driver.get(verify_email)
                    WebDriverWait(self.driver, self.t_o).until(
                        EC.presence_of_element_located(
                            (
                                By.XPATH,
                                "//h1[normalize-space()='Account Overview']",
                            )
                        )
                    )

                    if bool(self.config["utils"]["verbose"]):
                        self.sprint(
                            f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.GREEN}+{Fore.RESET}] {Fore.CYAN}Verified Email"
                        )

                    break

            try:
                if self.driver.find_element(
                    By.CSS_SELECTOR,
                    "#email-card > div.card-subtitle > div > div > div:nth-child(2) > span > span > span > a",
                ).is_displayed():
                    if bool(self.config["utils"]["verbose"]):
                        self.sprint(
                            f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.RED}-{Fore.RESET}] {Fore.CYAN}Could not verify email"
                        )

                    self.Email_Verified = False
            except:
                pass

        self.driver.get("https://account.battle.net/security")

        if self.config["account_settings"]["security_question"] in ["", False]:
            self.security_ans = "".join(
                random.choice(string.ascii_letters + string.digits) for _ in range(10)
            )
        else:
            self.security_ans = self.config["account_settings"]["security_question"]

        WebDriverWait(self.driver, self.t_o).until(
            EC.presence_of_element_located(
                (By.XPATH, "//a[normalize-space()='Select a Secret Question']")
            )
        )

        WebDriverWait(self.driver, self.t_o).until(
            EC.element_to_be_clickable(
                (By.XPATH, "//a[normalize-space()='Select a Secret Question']")
            )
        )

        self.driver.find_element(
            By.XPATH, "//a[normalize-space()='Select a Secret Question']"
        ).click()

        WebDriverWait(self.driver, self.t_o).until(
            EC.presence_of_element_located(
                (By.XPATH, "//select[@id='question-select']")
            )
        )

        self.driver.find_element(By.XPATH, "//select[@id='question-select']").click()

        WebDriverWait(self.driver, self.t_o).until(
            EC.presence_of_element_located(
                (
                    By.XPATH,
                    "/html/body/div[1]/main/section[2]/div/div[4]/div[2]/div/div[2]/form/div[1]/div[2]/select/option[2]",
                )
            )
        )

        self.driver.find_element(
            By.XPATH,
            "/html/body/div[1]/main/section[2]/div/div[4]/div[2]/div/div[2]/form/div[1]/div[2]/select/option[2]",
        ).click()

        WebDriverWait(self.driver, self.t_o).until(
            EC.presence_of_element_located((By.XPATH, "//input[@id='answer']"))
        )

        self.driver.find_element(By.XPATH, "//input[@id='answer']").send_keys(
            self.security_ans
        )

        WebDriverWait(self.driver, self.t_o).until(
            EC.presence_of_element_located((By.XPATH, "//button[@id='sqa-submit']"))
        )

        self.driver.find_element(By.XPATH, "//button[@id='sqa-submit']").click()

        if bool(self.config["utils"]["verbose"]):
            self.sprint(
                f"[{Fore.LIGHTBLUE_EX}{_time()}{Fore.RESET}][{Fore.GREEN}+{Fore.RESET}] {Fore.CYAN}Security Question/Answer Set To: {Fore.LIGHTMAGENTA_EX}{self.security_ans}"
            )

        thread_lock.acquire()
        Write.Print(
            f"[{_time()}][+] Created Account: {self.email}:{self.password}:{self.security_ans}\n",
            Colors.rainbow,
            interval=0.00,
        )
        with open("Accounts.txt", "a") as accounts:
            if hasattr(self, "Email_Verified"):
                accounts.write(
                    f"Non Email Verifed [ {self.email}:{self.password}:{self.security_ans} ]\n"
                )
            else:
                self.format = int(self.config["utils"]["account_format"])

                if self.format == 1:
                    accounts.write(
                        f"{self.email}:{self.password}:{self.security_ans}\n"
                    )
                elif self.format == 2:
                    accounts.write(
                        f"Email: {self.email} | Password: {self.password} | Security: {self.security_ans} | Battletag: {acc_username}\n"
                    )
                elif self.format == 3:
                    today = date.today()
                    accounts.write(
                        f"Email: {self.email} | Password: {self.password} | Security: {self.security_ans} | Date Made: {today.strftime(r'%d/%m/%Y')}\n"
                    )
                elif self.format == 4:
                    accounts.write(
                        f"Email: {self.email} | Password: {self.password} | Security: {self.security_ans}\n"
                    )
                else:
                    accounts.write(
                        f"[Email: {self.email}, Password: {self.password}, Security: {self.security_ans}]\n"
                    )

        global account_created
        account_created += 1

      

        thread_lock.release()

        self.driver.quit()

        return True

    def __main__(self):
        for _ in range(int(self.config["utils"]["iterations"])):
            threading.Thread(target=self.check_keys).start()
            self.__init_driver__()
            self.fill_forms()


with open("config.json", "r") as config:
    config = json.load(config)



print(
    Center.XCenter(
        Colorate.Vertical(
            Colors.blue_to_red,
            """
                                   
				
              ______           _                    ______                  
            .' ____ \         (_)                 .' ___  |                 
            | (___ \_|_ .--.  __  _ .--.  .--.   / .'   \_| .---.  _ .--.   
             _.____`.[ '/'`\ [  |[ `/'`\] .'`\ \ | |   ____/ /__\\[ `.-. |  
            | \____) || \__/ || | | |   | \__. | \ `.___]  | \__., | | | |  
             \______.'| ;.__/[___|___]   '.__.'   `._____.' '.__.'[___||__] 
                    [__|                                                   

                                                                                    
             
""",
            1,
        )
    )
)

Write.Print(
    "─══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════─\n",
    Colors.red,
    interval=0,
)

if config["utils"]["use_proxies"]:
    proxy = open("proxies.txt", "r").read().splitlines()
else:
    proxy = [False]

threads = []

for i in range(int(config["utils"]["thread_count"])):
    start_thread = threading.Thread(target=Generator(random.choice(proxy)).__main__)
    threads.append(start_thread)
    start_thread.start()

for thread in threads:
    thread.join()
