import os
from datetime import datetime

# CONFIGURAÇÕES DE LOG
BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

LOG_DIR = os.path.join(
    BASE_DIR,
    "logs"
)

AUDIT_LOG = os.path.join(
    LOG_DIR,
    "audit.log"
)


# FUNÇÕES AUXILIARES
def horario() -> str:

    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def safe_str(valor) -> str:

    try:
        return str(valor)

    except Exception:
        return repr(valor)


def limpar_campo(valor) -> str:

    texto = safe_str(
        valor
    )

    return (
        texto
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


# APAGAR LOG DE AUDITORIA
def apagar_audit_log():

    if not os.path.exists(
        AUDIT_LOG
    ):

        return False

    os.remove(
        AUDIT_LOG
    )

    return True


# REGISTRO DE AUDITORIA
def audit(
    evento: str,
    ip: str,
    detalhe: str = ""
) -> None:
    """
    TIMESTAMP | IP | EVENTO | DETALHE
    """
    os.makedirs(
        LOG_DIR,
        exist_ok=True
    )


    ip_seguro = limpar_campo(
        ip
    )

    evento_seguro = limpar_campo(
        evento
    )

    detalhe_seguro = limpar_campo(
        detalhe
    )


    with open(
        AUDIT_LOG,
        "a",
        encoding="utf-8",
        errors="replace"
    ) as arquivo_log:

        arquivo_log.write(
            f"{horario()} | "
            f"{ip_seguro} | "
            f"{evento_seguro} | "
            f"{detalhe_seguro}\n"
        )