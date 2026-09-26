from modo import (
    obter_modo,
    alterar_modo,
    modo_defesa_ativa,
    MODO_EDUCACIONAL,
    MODO_DEFESA_ATIVA
)


#AÇÕES DEFENSIVAS
ACAO_PERMITIR = "PERMITIR"

ACAO_BLOQUEAR_REQUISICAO = "BLOQUEAR_REQUISICAO"

ACAO_REJEITAR_CONTEUDO = "REJEITAR_CONTEUDO"

ACAO_NEGAR_ACESSO = "NEGAR_ACESSO"

ACAO_NEGAR_ARQUIVO = "NEGAR_ARQUIVO"

ACAO_LIMITAR_REQUISICOES = "LIMITAR_REQUISICOES"

ACAO_NENHUMA = "NENHUMA"


# RESPOSTAS DEFENSIVAS
RESPOSTAS_DEFENSIVAS = {

    "SQL INJECTION":
        ACAO_BLOQUEAR_REQUISICAO,

    "XSS":
        ACAO_REJEITAR_CONTEUDO,

    "IDOR":
        ACAO_NEGAR_ACESSO,

    "PATH TRAVERSAL":
        ACAO_BLOQUEAR_REQUISICAO,

    "FILE DISCLOSURE":
        ACAO_NEGAR_ARQUIVO,

    "BRUTEFORCE":
        ACAO_LIMITAR_REQUISICOES
}


#FUNÇÕES AUXILIARES
def normalizar_tipo_ataque(tipo_ataque):

    if tipo_ataque is None:
        return None

    return str(
        tipo_ataque
    ).strip().upper()


def obter_acao_defensiva(tipo_ataque):

    tipo_ataque = normalizar_tipo_ataque(
        tipo_ataque
    )

    return RESPOSTAS_DEFENSIVAS.get(
        tipo_ataque,
        ACAO_NENHUMA
    )


#AVALIAR EVENTO
def avaliar_evento(
    tipo_ataque,
    ip=None,
    endpoint=None
):

    tipo_ataque = normalizar_tipo_ataque(
        tipo_ataque
    )

    modo_atual = obter_modo()


    #MODO EDUCACIONAL
    if modo_atual == MODO_EDUCACIONAL:

        return {
            "modo": modo_atual,
            "ataque": tipo_ataque,
            "ip": ip,
            "endpoint": endpoint,
            "acao": ACAO_PERMITIR,
            "mitigar": False,
            "mensagem": (
                "Evento detectado no Modo Educacional. "
                "A atividade pode ser registrada e observada, "
                "mas nenhuma mitigação automática será aplicada."
            )
        }


    #DEFESA ATIVA

    if modo_defesa_ativa():

        acao = obter_acao_defensiva(
            tipo_ataque
        )


        #ATAQUE RECONHECIDO
        if acao != ACAO_NENHUMA:

            return {
                "modo": MODO_DEFESA_ATIVA,
                "ataque": tipo_ataque,
                "ip": ip,
                "endpoint": endpoint,
                "acao": acao,
                "mitigar": True,
                "mensagem": (
                    "Evento detectado com a Defesa Ativa "
                    "habilitada. Uma resposta defensiva "
                    "foi selecionada para esta categoria."
                )
            }


        #ATAQUE DESCONHECIDO
        return {
            "modo": MODO_DEFESA_ATIVA,
            "ataque": tipo_ataque,
            "ip": ip,
            "endpoint": endpoint,
            "acao": ACAO_NENHUMA,
            "mitigar": False,
            "mensagem": (
                "O evento foi recebido pela camada defensiva, "
                "mas não existe uma resposta automática "
                "configurada para esta categoria."
            )
        }


    #ESTADO OPERACIONAL INDEFINIDO

    return {
        "modo": modo_atual,
        "ataque": tipo_ataque,
        "ip": ip,
        "endpoint": endpoint,
        "acao": ACAO_NENHUMA,
        "mitigar": False,
        "mensagem": (
            "Não foi possível determinar uma resposta "
            "defensiva para o estado operacional atual."
        )
    }


#TESTES LOCAIS

if __name__ == "__main__":

    ataques_teste = [
        ("SQL INJECTION", "POST /login"),
        ("XSS", "POST /comentarios"),
        ("IDOR", "GET /perfil"),
        ("PATH TRAVERSAL", "GET /download"),
        ("FILE DISCLOSURE", "GET /download"),
        ("BRUTEFORCE", "POST /login"),
        ("TESTE", "/teste")
    ]


    print("CCTE - TESTE DA DEFESA ATIVA")


    #TESTE MODO EDUCACIONAL
    alterar_modo(
        MODO_EDUCACIONAL
    )

    print(
        "\nMODO:",
        obter_modo()
    )


    for ataque, endpoint in ataques_teste:

        resultado = avaliar_evento(
            ataque,
            ip="127.0.0.1",
            endpoint=endpoint
        )

        print(
            ataque,
            "->",
            resultado
        )


    # TESTE DEFESA ATIVA
    alterar_modo(
        MODO_DEFESA_ATIVA
    )

    print(
        "\nMODO:",
        obter_modo()
    )


    for ataque, endpoint in ataques_teste:

        resultado = avaliar_evento(
            ataque,
            ip="127.0.0.1",
            endpoint=endpoint
        )

        print(
            ataque,
            "->",
            resultado
        )