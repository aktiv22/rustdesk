#!/usr/bin/env python3
"""BancControl: genereaza chei si semneaza profilul custom.txt.

  sign_config.py --gen-keys CALE_CHEIE_PRIVATA   -> scrie cheia privata (chmod 600), tipareste cheia publica (base64)
  sign_config.py profil.json CALE_CHEIE_PRIVATA  -> tipareste continutul pentru custom.txt (base64 al mesajului semnat)

Cheia privata NU se pune in depozit. Cheia publica se pune in BC_CONFIG_PUBKEY (src/common.rs).
"""
import base64, json, os, sys
from nacl.signing import SigningKey


def gen_keys(path):
    sk = SigningKey.generate()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(base64.b64encode(bytes(sk)))
    return base64.b64encode(bytes(sk.verify_key)).decode()


def sign_profile(profile_path, key_path):
    with open(profile_path, "rb") as f:
        payload = json.dumps(json.loads(f.read()), separators=(",", ":")).encode()
    with open(key_path, "rb") as f:
        sk = SigningKey(base64.b64decode(f.read()))
    # sign() intoarce semnatura (64 de octeti) + mesajul = formatul "combined" al libsodium
    return base64.b64encode(bytes(sk.sign(payload))).decode()


def main(argv):
    if len(argv) == 3 and argv[1] == "--gen-keys":
        print(gen_keys(argv[2]))
    elif len(argv) == 3:
        print(sign_profile(argv[1], argv[2]))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
