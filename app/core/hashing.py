"""
Hashing de contraseñas con `bcrypt` directamente (sin passlib, por incompatibilidades
conocidas de passlib con versiones recientes de bcrypt).
"""

import bcrypt

# Factor de costo del algoritmo: cada punto extra duplica el tiempo de cómputo del hash.
# 12 es el piso recomendado actualmente (2026) para no facilitarle un ataque de fuerza bruta
# offline a quien robe la base de datos, manteniendo el login en un tiempo razonable (~250ms).
_RONDAS_BCRYPT = 12


def hashear_password(password_plano: str) -> str:
    """
    Genera un hash irreversible de la contraseña. bcrypt incluye el salt dentro del propio
    hash resultante (no hace falta guardarlo aparte) y ese salt es distinto en cada llamada,
    así que dos usuarios con la misma contraseña nunca van a tener el mismo hash en la base
    de datos — eso evita que un atacante detecte contraseñas repetidas comparando hashes.
    """
    password_bytes = password_plano.encode("utf-8")
    salt = bcrypt.gensalt(rounds=_RONDAS_BCRYPT)
    hash_bytes = bcrypt.hashpw(password_bytes, salt)
    return hash_bytes.decode("utf-8")


def verificar_password(password_plano: str, password_hash: str) -> bool:
    """
    Compara la contraseña ingresada contra el hash guardado. Usa `bcrypt.checkpw`, que hace
    una comparación de tiempo constante internamente, en vez de rehashear y comparar strings
    con `==` (lo que filtraría información por temporización).
    """
    try:
        return bcrypt.checkpw(password_plano.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        # Un hash con formato corrupto o inválido nunca debe tumbar el login con un 500;
        # simplemente se lo trata como "no coincide".
        return False
