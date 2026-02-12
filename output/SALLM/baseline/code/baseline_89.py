from typing import Optional

def sign(pre_key: bytes, imsg: bytes, alg=hashlib.sha256) -> Optional[bytes]:
    ...

def verify(msg: bytes, sig: bytes, pre_key: bytes, alg=hashlib.sha256) -> bool:
    ...

