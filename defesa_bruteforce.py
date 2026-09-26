import time
import math

#CONFIGURAÇÕES DO RATE LIMIT
TEMPO_BLOQUEIO = 30

ips_bloqueados = {}


#BLOQUEAR IP
def bloquear_ip(
    ip,
    duracao=TEMPO_BLOQUEIO
):

    agora = time.time()

    expira_em = agora + duracao

    ips_bloqueados[ip] = expira_em

    return {
        "ip": ip,
        "bloqueado": True,
        "duracao": duracao,
        "expira_em": expira_em
    }


#VERIFICAR BLOQUEIO
def verificar_bloqueio(ip):

    if ip not in ips_bloqueados:

        return {
            "bloqueado": False,
            "tempo_restante": 0
        }


    agora = time.time()

    expira_em = ips_bloqueados[ip]


    #BLOQUEIO EXPIRADO
    if agora >= expira_em:

        del ips_bloqueados[ip]

        return {
            "bloqueado": False,
            "tempo_restante": 0
        }


    tempo_restante = math.ceil(
        expira_em - agora
    )


    return {
        "bloqueado": True,
        "tempo_restante": tempo_restante
    }


#LIBERAR IP
def liberar_ip(ip):

    if ip in ips_bloqueados:

        del ips_bloqueados[ip]

        return True


    return False


#LIMPAR TODOS OS BLOQUEIOS
def limpar_bloqueios():

    quantidade = len(
        ips_bloqueados
    )

    ips_bloqueados.clear()

    return quantidade