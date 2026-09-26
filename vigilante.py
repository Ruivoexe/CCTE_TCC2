import os
from datetime import datetime
from collections import defaultdict
from defesa_ativa import avaliar_evento

# CONFIGURAÇÕES DE LOG
BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

LOG_DIR = os.path.join(
    BASE_DIR,
    "logs"
)

LOG_FILE = os.path.join(
    LOG_DIR,
    "security.log"
)

# APAGAR LOG DE SEGURANÇA
def apagar_security_log():

    if not os.path.exists(
        LOG_FILE
    ):

        return False

    os.remove(
        LOG_FILE
    )

    return True


# ROTAS MONITORADAS
ROTAS_LABORATORIO = {
    "/login",
    "/registro",
    "/perfil",
    "/comentarios",
    "/download"
}


# CONFIGURAÇÕES DE BRUTE FORCE
tentativas_login = defaultdict(list)

MAX_TENTATIVAS_LOGIN = 10

INTERVALO_BRUTEFORCE = 20

# LIMPAR TENTATIVAS DE LOGIN
def limpar_tentativas_login():

    quantidade = sum(
        len(tentativas)
        for tentativas in tentativas_login.values()
    )

    tentativas_login.clear()

    return quantidade


# ASSINATURAS DE ATAQUE
SQLI = [
    "' or ",
    "\" or ",
    " or 1=1",
    " or '1'='1",
    "\" or \"1\"=\"1",
    "--",
    "/*",
    "*/",
    "union select",
    "sleep(",
    "benchmark(",
]

XSS = [
    "<script",
    "onerror",
    "onload",
    "<img",
    "<svg",
    "<iframe",
    "javascript:"
]

TRAVERSAL = [
    "../",
    "..\\",
    "%2f",
    "%5c"
]

SENSIVEL = [
    "database.db",
    ".db",
    ".sqlite",
    ".env",
    "config",
    "passwd",
    "shadow",
    "users.txt"
]


#AUXILIARES
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


def args_to_str(args) -> str:

    if not args:
        return ""

    try:

        return "&".join(
            f"{chave}={valor}"
            for chave, valor in args.items()
        )

    except Exception:

        return safe_str(
            args
        )


#DETECÇÃO POR ASSINATURA
def detectar_payload(payload_lower: str):

    for padrao in SQLI:

        if padrao in payload_lower:
            return "SQL INJECTION"


    for padrao in XSS:

        if padrao in payload_lower:
            return "XSS"


    for padrao in TRAVERSAL:

        if padrao in payload_lower:
            return "PATH TRAVERSAL"


    return None


#DETECÇÃO DE BRUTE FORCE
def detectar_bruteforce(
    ip: str,
    endpoint: str,
    method: str
):

    if endpoint != "/login":
        return None


    if method != "POST":
        return None


    agora = datetime.now().timestamp()


    tentativas_login[ip].append(
        agora
    )


    tentativas_login[ip] = [
        timestamp
        for timestamp in tentativas_login[ip]
        if agora - timestamp <= INTERVALO_BRUTEFORCE
    ]


    if len(
        tentativas_login[ip]
    ) >= MAX_TENTATIVAS_LOGIN:

        return "BRUTEFORCE"


    return None


# DETECÇÃO DE IDOR
def detectar_idor(
    endpoint: str,
    args,
    session_user
):

    if endpoint != "/perfil":
        return None


    if not args or "id" not in args:
        return None


    if session_user is None:
        return None


    try:

        id_solicitado = int(
            args.get("id")
        )

        id_logado = int(
            session_user
        )

    except (TypeError, ValueError):

        return None


    if id_solicitado != id_logado:

        return "IDOR"


    return None


# DETECÇÃO DE DOWNLOAD SUSPEITO

def detectar_download(
    endpoint: str,
    args
):

    if endpoint != "/download":
        return None


    if not args or "file" not in args:
        return None


    arquivo = safe_str(
        args.get("file")
    ).lower()


    for padrao in TRAVERSAL:

        if padrao in arquivo:

            return "PATH TRAVERSAL"


    for arquivo_sensivel in SENSIVEL:

        if arquivo_sensivel in arquivo:

            return "FILE DISCLOSURE"


    return None


# ANÁLISE DA REQUISIÇÃO
def analisar_requisicao(
    ip,
    endpoint,
    payload,
    args,
    session_user,
    method="GET"
):

    # IGNORAR ROTAS FORA DO LABORATÓRIO
    if endpoint not in ROTAS_LABORATORIO:
        return None


    ataques = []


    payload_str = safe_str(
        payload
    )

    payload_lower = payload_str.lower()


    args_str = args_to_str(
        args
    )

    args_lower = args_str.lower()


    # DETECÇÃO NO PAYLOAD

    tipo_payload = detectar_payload(
        payload_lower
    )


    if tipo_payload:

        ataques.append(
            tipo_payload
        )


    # DETECÇÃO NOS ARGUMENTOS GET
    tipo_args = detectar_payload(
        args_lower
    )


    if (
        tipo_args
        and tipo_args not in ataques
    ):

        ataques.append(
            tipo_args
        )


    # DETECÇÃO DE BRUTE FORCE
    brute = detectar_bruteforce(
        ip,
        endpoint,
        method
    )


    if brute:

        ataques.append(
            brute
        )


    # DETECÇÃO DE IDOR

    idor = detectar_idor(
        endpoint,
        args,
        session_user
    )


    if idor:

        ataques.append(
            idor
        )


    # DETECÇÃO DE DOWNLOAD
    download = detectar_download(
        endpoint,
        args
    )


    if download:

        ataques.append(
            download
        )


    # NENHUM ATAQUE

    if not ataques:
        return None


    # REMOVER DUPLICIDADES
    ataques_unicos = sorted(
        set(
            ataques
        )
    )


    # DECISÕES DEFENSIVAS
    decisoes = []


    for ataque in ataques_unicos:

        decisao = avaliar_evento(
            ataque,
            ip=safe_str(ip),
            endpoint=(
                f"{safe_str(method)} "
                f"{safe_str(endpoint)}"
            )
        )

        decisoes.append(
            decisao
        )


    # RESULTADO DA ANÁLISE
    return {
        "ip": safe_str(ip),

        "endpoint": safe_str(endpoint),

        "method": safe_str(method),

        "payload": payload_str,

        "args": args_str,

        "session_user": safe_str(
            session_user
        ),

        "ataques": ataques_unicos,

        "decisoes": decisoes
    }


# REGISTRO DO RESULTADO
def registrar_resultado(resultado):

    if not resultado:
        return


    os.makedirs(
        LOG_DIR,
        exist_ok=True
    )


    ataques = resultado.get(
        "ataques",
        []
    )


    if not ataques:
        return


    tipos = ",".join(
        ataques
    )


    ip = limpar_campo(
        resultado.get(
            "ip",
            ""
        )
    )


    endpoint = limpar_campo(
        resultado.get(
            "endpoint",
            ""
        )
    )


    method = limpar_campo(
        resultado.get(
            "method",
            "GET"
        )
    )


    payload = limpar_campo(
        resultado.get(
            "payload",
            ""
        )
    )


    args = limpar_campo(
        resultado.get(
            "args",
            ""
        )
    )


    session_user = limpar_campo(
        resultado.get(
            "session_user",
            "None"
        )
    )

    tipos = limpar_campo(
        tipos
    )


    decisoes = resultado.get(
        "decisoes",
        []
    )


    # SECURITY.LOG
    with open(
        LOG_FILE,
        "a",
        encoding="utf-8",
        errors="replace"
    ) as arquivo_log:

        arquivo_log.write(
            f"{horario()} | "
            f"{ip} | "
            f"{method} {endpoint} | "
            f"{tipos} | "
            f"payload={payload} | "
            f"args={args} | "
            f"session_user={session_user}\n"
        )


    #ALERTA NO TERMINAL
    print(
        f"[ALERTA] "
        f"{tipos} "
        f"DETECTADO(S) DE "
        f"{ip}"
    )


    #DECISÕES NO TERMINAL
    for decisao in decisoes:

        print(
            f"[DECISAO] "
            f"modo={decisao['modo']} | "
            f"ataque={decisao['ataque']} | "
            f"acao={decisao['acao']} | "
            f"mitigar={decisao['mitigar']}"
        )


#PIPELINE DE COMPATIBILIDADE

def registrar(
    ip,
    endpoint,
    payload,
    args,
    session_user,
    method="GET"
):

    resultado = analisar_requisicao(
        ip=ip,
        endpoint=endpoint,
        payload=payload,
        args=args,
        session_user=session_user,
        method=method
    )


    registrar_resultado(
        resultado
    )


    return resultado