# Copyright (C) 2025 PandaEver
# This code is licensed under GNU AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html).
# See the LICENSE file for details.
import argparse, os, re, secrets, datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

INFO = {
    "version": "1.0",
    "author": "VD_Priv8 (VD171)",
    "recoded": "PandaEver",
    "github": "https://github.com/JustPandaEver"
}

def vd_random_serial(num):
    return secrets.token_hex(num)

def generate_ecdsa_key():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_key, private_pem.decode('utf-8'), public_pem.decode('utf-8')

def generate_csr(private_key, subject_title, serial_subject):
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.TITLE, subject_title),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, serial_subject),
    ]))
    builder = builder.sign(private_key, hashes.SHA256(), default_backend())
    csr_pem = builder.public_bytes(serialization.Encoding.PEM)
    return csr_pem.decode('utf-8')

def sign_certificate(ca_cert_pem, ca_private_key_pem, csr_pem, serial_ca_int, days):
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode('utf-8'), default_backend())
    ca_private_key = serialization.load_pem_private_key(ca_private_key_pem.encode('utf-8'), password=None, backend=default_backend())
    csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'), default_backend())
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(serial_ca_int)
    builder = builder.not_valid_before(datetime.datetime.now(datetime.UTC))
    builder = builder.not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=int(days)))
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
    builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
    new_cert = builder.sign(ca_private_key, hashes.SHA256(), default_backend())
    new_cert_pem = new_cert.public_bytes(serialization.Encoding.PEM)
    return new_cert_pem.decode('utf-8')

def banner():
    return f"KeyBox Generator v{INFO['version']}\nby {INFO['author']}\nRecoded by: {INFO['recoded']}\nGitHub: {INFO['github']}\n"

def main():
    vd_parser = argparse.ArgumentParser(epilog=banner(), formatter_class=argparse.RawDescriptionHelpFormatter)
    vd_parser.add_argument("--file", default="keybox.xml", help="Keybox file path")
    vd_parser.add_argument("--days", default="365", help="How many days for expiring the new certificate")
    vd_parser.add_argument("--title", default="TEE", help="Title for the new certificate. Default is TEE for a valid title")
    vd_parser.add_argument("--serial_ca", default=vd_random_serial(8), help="Set the unique Serial for the new certificate. Must be hex format. Default is random for a valid Serial")
    vd_parser.add_argument("--serial_subject", default=vd_random_serial(16), help="Set serialNumber in Subject for the new certificate. default is random for valid serialNumber")
    vd_parser.add_argument("--out", default="keybox.new.xml", help="New Keybox file path")
    vd_args = vd_parser.parse_args()

    try:
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        exit("Error: The 'cryptography' library is not installed. Please install it using 'pip install cryptography'")

    if not os.path.exists(vd_args.file):
        exit(f"Error: File '{vd_args.file}' not found! Use: --file")

    try:
        vd_serial_ca_int = int(vd_args.serial_ca, 16)
    except ValueError:
        exit("Error: serial_ca must be a valid hex string!")

    with open(vd_args.file, encoding="utf-8") as vd_file:
        vd_content = vd_file.read()

    vd_content = re.sub(r"[\r\n]*\s*<Key algorithm=\"rsa\">.*?</Key>(\s*[\r\n]*)", r"\1", vd_content, flags=re.DOTALL)
    if "<Key algorithm=\"ecdsa\">" not in vd_content:
        exit("Error: ECDSA Key not found!")

    vd_key_match = re.search(r"<PrivateKey format=\"pem\">(.*?)</PrivateKey>", vd_content, re.DOTALL)
    vd_cert_match = re.search(r"(<Certificate format=\"pem\">(.*?)</Certificate>)", vd_content, re.DOTALL)
    vd_number_match = re.search(r"(<NumberOfCertificates>(.*?)</NumberOfCertificates>)", vd_content, re.DOTALL)

    if not all([vd_key_match, vd_cert_match, vd_number_match]):
        exit("Error: Missing required elements!")

    ca_private_key_pem = re.sub(r"^\s+|\s+$", "", re.sub(r"\s*([\r\n]+)\s*", r"\1", vd_key_match.group(1)))
    ca_cert_pem = re.sub(r"^\s+|\s+$", "", re.sub(r"\s*([\r\n]+)\s*", r"\1", vd_cert_match.group(2)))

    new_private_key, new_public_key, new_private_pem, new_public_pem = generate_ecdsa_key()
    new_csr_pem = generate_csr(new_private_key, vd_args.title, vd_args.serial_subject)
    new_cert_pem = sign_certificate(ca_cert_pem, ca_private_key_pem, new_csr_pem, vd_serial_ca_int, vd_args.days)
    vd_number_new = vd_number_match.group(1).replace(vd_number_match.group(2), str(int(vd_number_match.group(2)) + 1))
    vd_cert_new = vd_cert_match.group(1).replace(vd_cert_match.group(2), new_cert_pem) + "\n" + vd_cert_match.group(1)

    with open(vd_args.out, "w") as vd_file:
        vd_file.write(vd_content.replace(vd_number_match.group(1), vd_number_new).replace(vd_key_match.group(1), new_private_pem.replace('-----BEGIN PRIVATE KEY-----', '-----BEGIN EC PRIVATE KEY-----').replace('-----END PRIVATE KEY-----', '-----END EC PRIVATE KEY-----')).replace(vd_cert_match.group(1), vd_cert_new))
    print(f"{banner()}New keybox: {vd_args.out}.")

if __name__ == "__main__":
    main()
