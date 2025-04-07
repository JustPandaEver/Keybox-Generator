# Copyright (C) 2025 VD_Priv8 (VD171)
# This code is licensed under GNU AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html).
# See the LICENSE file for details.

import argparse, os, re, secrets, shutil, subprocess

INFO = {
    "version": "1.2",
    "author": "VD_Priv8 (VD171)",
    "github": "https://github.com/VD171",
    "telegram": "https://t.me/VD_Priv8"
}

def vd_random_serial(num):
    return secrets.token_hex(num)

def main():
    vd_parser = argparse.ArgumentParser(epilog=f"KeyBox Generator v{INFO['version']}\nby {INFO['author']}\nGitHub: {INFO['github']}\nTelegram: {INFO['telegram']}\n ", formatter_class=argparse.RawDescriptionHelpFormatter)
    vd_parser.add_argument("--file", default="keybox.xml", help="Keybox file path")
    vd_parser.add_argument("--days", default="365", help="How many days for expiring the new certificate")
    vd_parser.add_argument("--title", default="TEE", help="Title for the new certificate. Default is TEE for a valid title")
    vd_parser.add_argument("--serial_ca", default=vd_random_serial(8), help="Set the unique Serial for the new certificate. Must be hex format. Default is random for a valid Serial")
    vd_parser.add_argument("--serial_subject", default=vd_random_serial(16), help="Set serialNumber in Subject for the new certificate. default is random for valid serialNumber")
    vd_parser.add_argument("--out", default="keybox.new.xml", help="New Keybox file path")
    vd_args = vd_parser.parse_args()

    if not shutil.which("openssl"):  
        exit("Error: OpenSSL not found! Try running in Termux!")

    if not os.path.exists(vd_args.file):
        exit(f"Error: File '{vd_args.file}' not found! Use: --file")

    try:
        vd_serial_ca = int(vd_args.serial_ca, 16)
    except ValueError:
        exit("Error: serial_ca must be a valid hex string!")

    vd_temp_key = ".temp.private.key"
    vd_temp_cert = ".temp.certificate.pem"
    vd_temp_new_key = ".temp.new.private.key"
    vd_temp_new_csr = ".temp.new.certificate.csr"

    with open(vd_args.file, encoding="utf-8") as vd_file:
        vd_content = vd_file.read()

    vd_content = re.sub(r"[\r\n]*\s*<Key algorithm=\"rsa\">.*?</Key>(\s*[\r\n]*)", r"\1", vd_content, flags=re.DOTALL)
    if "<Key algorithm=\"ecdsa\">" not in vd_content:
        exit("Error: ECDSA Key not found!")

    vd_key = re.search(r"<PrivateKey format=\"pem\">(.*?)</PrivateKey>", vd_content, re.DOTALL)
    vd_cert = re.search(r"(<Certificate format=\"pem\">(.*?)</Certificate>)", vd_content, re.DOTALL)
    vd_number = re.search(r"(<NumberOfCertificates>(.*?)</NumberOfCertificates>)", vd_content, re.DOTALL)

    if not all([vd_key, vd_cert, vd_number]):
        exit("Error: Missing required elements!")

    vd_new_key = subprocess.run("openssl ecparam -name prime256v1 -genkey", shell=True, capture_output=True, text=True, check=True).stdout.strip()
    vd_new_key = re.search(r"(-----BEGIN EC PRIVATE KEY-----.*?-----END EC PRIVATE KEY-----)", vd_new_key, re.DOTALL).group(1)

    for vd_temp, vd_data in {vd_temp_key: vd_key.group(1), vd_temp_cert: vd_cert.group(2), vd_temp_new_key: vd_new_key}.items():
        with open(vd_temp, "w") as vd_file:
            vd_file.write(re.sub(r"^\s+|\s+$", "", re.sub(r"\s*([\r\n]+)\s*", r"\1", vd_data)))
        if not os.path.exists(vd_temp):
            exit(f"Error: Can't create {vd_temp}!")

    subprocess.run(f"openssl req -new -key {vd_temp_new_key} -out {vd_temp_new_csr} -subj '/title={vd_args.title}/serialNumber={vd_args.serial_subject}'", shell=True, check=True)
    vd_new_cert = subprocess.run(f"openssl x509 -req -in {vd_temp_new_csr} -CA {vd_temp_cert} -CAkey {vd_temp_key} -CAcreateserial -set_serial {vd_serial_ca} -days {vd_args.days} -sha256", shell=True, capture_output=True, text=True, check=True).stdout.strip()

    vd_number_new = vd_number.group(1).replace(vd_number.group(2), str(int(vd_number.group(2)) + 1))
    vd_cert_new = vd_cert.group(1).replace(vd_cert.group(2), vd_new_cert) + "\n" + vd_cert.group(1)

    with open(vd_args.out, "w") as vd_file:
        vd_file.write(vd_content.replace(vd_number.group(1), vd_number_new).replace(vd_key.group(1), vd_new_key).replace(vd_cert.group(1), vd_cert_new))

    print(f"New keybox: {vd_args.out}.")
    for vd_temp in [vd_temp_key, vd_temp_cert, vd_temp_new_key, vd_temp_new_csr, ".temp.certificate.srl"]:
        try:
            os.remove(vd_temp)
        except FileNotFoundError:
            pass

if __name__ == "__main__":
    main()
