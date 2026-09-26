"""
Controle dos modos operacionais do CCTE.

O sistema possui dois modos:

EDUCACIONAL
O ambiente mantém as vulnerabilidades exploráveis.
Os eventos são monitorados, detectados e registrados,
mas nenhuma mitigação automática é aplicada.

DEFESA_ATIVA
O ambiente mantém o monitoramento e a detecção,
porém habilita mecanismos automáticos de resposta
defensiva.

O modo operacional não é persistente.
Sempre que o processo Flask for reiniciado,
o sistema retorna automaticamente para EDUCACIONAL.
"""


#DEFINIÇÃO DOS MODOS
MODO_EDUCACIONAL = "EDUCACIONAL"

MODO_DEFESA_ATIVA = "DEFESA_ATIVA"


#MODOS PERMITIDOS
MODOS_VALIDOS = (
    MODO_EDUCACIONAL,
    MODO_DEFESA_ATIVA
)


#ESTADO ATUAL
MODO_ATUAL = MODO_EDUCACIONAL


# NORMALIZAR MODO
def normalizar_modo(modo):

    if modo is None:
        return None

    return str(
        modo
    ).strip().upper()


#VALIDAR MODO
def modo_valido(modo):

    modo = normalizar_modo(
        modo
    )

    return modo in MODOS_VALIDOS


# OBTER MODO ATUAL
def obter_modo():

    return MODO_ATUAL


# ALTERAR MODO
def alterar_modo(novo_modo):

    global MODO_ATUAL

    novo_modo = normalizar_modo(
        novo_modo
    )


    if not modo_valido(
        novo_modo
    ):

        return {
            "sucesso": False,
            "anterior": MODO_ATUAL,
            "atual": MODO_ATUAL
        }


    modo_anterior = MODO_ATUAL

    MODO_ATUAL = novo_modo


    return {
        "sucesso": True,
        "anterior": modo_anterior,
        "atual": MODO_ATUAL
    }


#RESTAURAR MODO INICIAL
def restaurar_modo_inicial():

    return alterar_modo(
        MODO_EDUCACIONAL
    )


#VERIFICAR MODO EDUCACIONAL
def modo_educacional():

    return MODO_ATUAL == MODO_EDUCACIONAL


#VERIFICAR DEFESA ATIVA
def modo_defesa_ativa():

    return MODO_ATUAL == MODO_DEFESA_ATIVA


# DESCRIÇÃO DO MODO
def descricao_modo(modo=None):

    if modo is None:

        modo = MODO_ATUAL


    modo = normalizar_modo(
        modo
    )


    if modo == MODO_EDUCACIONAL:

        return (
            "Modo Educacional: as vulnerabilidades permanecem "
            "exploráveis enquanto o sistema monitora, detecta "
            "e registra os eventos. Nenhuma ação automática "
            "de mitigação é aplicada."
        )


    if modo == MODO_DEFESA_ATIVA:

        return (
            "Modo Defesa Ativa: o sistema mantém o monitoramento "
            "e a detecção dos eventos e habilita mecanismos "
            "automáticos de resposta defensiva."
        )


    return (
        "Modo operacional desconhecido."
    )


#TESTES
if __name__ == "__main__":

    print(
        "CCTE - TESTE DOS MODOS OPERACIONAIS"
    )


    print(
        "\nModo inicial:",
        obter_modo()
    )


    print(
        "\nAlterando para DEFESA_ATIVA"
    )

    print(
        alterar_modo(
            MODO_DEFESA_ATIVA
        )
    )


    print(
        "Modo atual:",
        obter_modo()
    )


    print(
        "\nRestaurando modo inicial"
    )

    print(
        restaurar_modo_inicial()
    )


    print(
        "Modo atual:",
        obter_modo()
    )


    print(
        "\nTeste de modo inválido"
    )

    print(
        alterar_modo(
            "OUTRO"
        )
    )


    print(
        "Modo atual:",
        obter_modo()
    )