"""
Hashing de contraseñas con `bcrypt` directamente (sin passlib, por incompatibilidades
conocidas de passlib con versiones recientes de bcrypt).
"""

import bcrypt

_RONDAS_BCRYPT = 12


def hashear_password(password_plano: str) -> str:
    """
    Genera un hash irreversible de la contraseña. bcrypt incluye el salt dentro del propio
    hash resultante y ese salt es distinto en cada llamada,
    eso evita que un atacante detecte contraseñas repetidas comparando hashes.
    """
    password_bytes = password_plano.encode("utf-8")
    salt = bcrypt.gensalt(rounds=_RONDAS_BCRYPT)
    hash_bytes = bcrypt.hashpw(password_bytes, salt)
    return hash_bytes.decode("utf-8")


def verificar_password(password_plano: str, password_hash: str) -> bool:
    """
    Compara la contraseña ingresada contra el hash guardado. Usa `bcrypt.checkpw`, que hace
    una comparación de tiempo constante.
    """
    try:
        return bcrypt.checkpw(password_plano.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False
