import os
from datetime import datetime
from collections import Counter

# CAMINHOS DO PROJETO
FORENSE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

BASE_DIR = os.path.dirname(
    FORENSE_DIR
)

AUDIT_LOG = os.path.join(
    BASE_DIR,
    "logs",
    "audit.log"
)

SECURITY_LOG = os.path.join(
    BASE_DIR,
    "logs",
    "security.log"
)

# CONFIGURAÇÕES
FORMATO_TIMESTAMP = "%Y-%m-%d %H:%M:%S"


# FUNÇÕES AUXILIARES
def verificar_logs():
    """
    Exibe os caminhos utilizados pelo módulo forense
    e informa se os arquivos de log existem.
    """

    print("Raiz do projeto:")
    print(BASE_DIR)

    print("\nAudit log:")
    print(AUDIT_LOG)
    print(
        "Existe:",
        os.path.exists(AUDIT_LOG)
    )

    print("\nSecurity log:")
    print(SECURITY_LOG)
    print(
        "Existe:",
        os.path.exists(SECURITY_LOG)
    )


def remover_prefixo(
    texto,
    prefixo
):

    if texto.startswith(prefixo):
        return texto[len(prefixo):]

    return texto


def timestamp_para_datetime(timestamp):

    try:

        return datetime.strptime(
            timestamp,
            FORMATO_TIMESTAMP
        )

    except (ValueError, TypeError):

        return datetime.min


# PARSER DO AUDIT.LOG
def parse_linha_audit(linha):
    """
    Formato esperado:

    TIMESTAMP | IP | EVENTO | DETALHES
    """

    linha = linha.strip()

    if not linha:
        return None


    partes = linha.split(
        " | ",
        3
    )


    if len(partes) != 4:
        return None


    return {
        "timestamp": partes[0],
        "ip": partes[1],
        "tipo": partes[2],
        "detalhes": partes[3],
        "origem": "audit"
    }


# CARREGAR AUDIT.LOG
def carregar_audit():

    eventos = []


    if not os.path.exists(
        AUDIT_LOG
    ):
        return eventos


    with open(
        AUDIT_LOG,
        "r",
        encoding="utf-8",
        errors="replace"
    ) as arquivo:

        for linha in arquivo:

            evento = parse_linha_audit(
                linha
            )

            if evento:

                eventos.append(
                    evento
                )


    return eventos


# PARSER DO SECURITY.LOG
def parse_linha_security(linha):
    """
    TIMESTAMP | IP | METHOD ENDPOINT | TIPO |
    payload=... | args=... | session_user=...
    """

    linha = linha.strip()

    if not linha:
        return None


    partes = linha.split(
        " | "
    )


    if len(partes) < 7:
        return None


    timestamp = partes[0]

    ip = partes[1]

    endpoint = partes[2]

    tipo = partes[3]


    # CAMPOS FINAIS
    args = partes[-2]

    session_user = partes[-1]


    # PAYLOAD
    payload = " | ".join(
        partes[4:-2]
    )


    return {
        "timestamp": timestamp,
        "ip": ip,
        "endpoint": endpoint,
        "tipo": tipo,

        "payload": remover_prefixo(
            payload,
            "payload="
        ),

        "args": remover_prefixo(
            args,
            "args="
        ),

        "session_user": remover_prefixo(
            session_user,
            "session_user="
        ),

        "origem": "security"
    }


# CARREGAR SECURITY.LOG
def carregar_security():

    eventos = []


    if not os.path.exists(
        SECURITY_LOG
    ):
        return eventos


    with open(
        SECURITY_LOG,
        "r",
        encoding="utf-8",
        errors="replace"
    ) as arquivo:

        for linha in arquivo:

            evento = parse_linha_security(
                linha
            )

            if evento:

                eventos.append(
                    evento
                )


    return eventos


# TIMELINE FORENSE
def carregar_timeline():

    eventos = []


    eventos.extend(
        carregar_audit()
    )

    eventos.extend(
        carregar_security()
    )


    eventos.sort(
        key=lambda evento:
        timestamp_para_datetime(
            evento.get(
                "timestamp"
            )
        )
    )


    return eventos


# ESTATÍSTICAS DE ATAQUES
def contar_ataques():

    eventos = carregar_security()

    contador = Counter()


    for evento in eventos:

        tipos = evento.get(
            "tipo",
            ""
        )


        if not tipos:
            continue


        # UM EVENTO PODE POSSUIR
        # MAIS DE UMA CLASSIFICAÇÃO
        for tipo in tipos.split(","):

            tipo = tipo.strip()


            if tipo:

                contador[tipo] += 1


    return contador


# EXECUÇÃO DE TESTE
if __name__ == "__main__":

    verificar_logs()


    print(
        "\n========================================"
    )

    print(
        "AUDIT.LOG"
    )

    print(
        "========================================"
    )


    eventos_audit = carregar_audit()


    print(
        f"Eventos encontrados: "
        f"{len(eventos_audit)}"
    )


    print(
        "\n========================================"
    )

    print(
        "SECURITY.LOG"
    )

    print(
        "========================================"
    )


    eventos_security = carregar_security()


    print(
        f"Eventos encontrados: "
        f"{len(eventos_security)}"
    )


    print(
        "\n========================================"
    )

    print(
        "TIMELINE FORENSE"
    )

    print(
        "========================================"
    )


    timeline = carregar_timeline()


    print(
        f"Total de eventos: "
        f"{len(timeline)}"
    )


    print(
        "\nÚltimos 10 eventos:"
    )


    for evento in timeline[-10:]:

        print(
            evento
        )


    print(
        "\n========================================"
    )

    print(
        "ESTATÍSTICAS DE ATAQUES"
    )

    print(
        "========================================"
    )


    ataques = contar_ataques()


    if not ataques:

        print(
            "Nenhum ataque registrado."
        )


    else:

        for tipo, quantidade in ataques.items():

            print(
                f"{tipo}: {quantidade}"
            )