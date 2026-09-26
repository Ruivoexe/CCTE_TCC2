from collections import Counter

try:

    from .parse import (
        carregar_audit,
        carregar_security,
        carregar_timeline,
        contar_ataques
    )

except ImportError:

    from parse import (
        carregar_audit,
        carregar_security,
        carregar_timeline,
        contar_ataques
    )


# EVENTOS RELEVANTES

EVENTOS_DEFENSIVOS = {
    "DEFESA_BLOQUEIO_APLICADO",
    "DEFESA_LIMPEZA_XSS",
    "DEFESA_LIMPEZA_XSS_FALHA",
    "DEFESA_LIMITE_REQUISICOES_ATIVADO",
    "DEFESA_REQUISICAO_LIMITADA"
}


EVENTOS_MODO = {
    "MODO_ALTERADO",
    "MODO_MANTIDO",
    "MODO_INVALIDO"
}


EVENTOS_RESTAURACAO = {
    "AMBIENTE_RESTAURADO",
    "AMBIENTE_RESTAURACAO_FALHA"
}


EVENTOS_AUDIT_RELEVANTES = {
    "LOGIN_SUCESSO",
    "LOGIN_FALHA",
    "SESSAO_ENCERRADA",

    "USUARIO_CRIADO",
    "USUARIO_DUPLICADO",
    "CAMPO_VAZIO",

    "PAGINA_BLOQUEADA_SEM_SESSAO",

    "COMENTARIO_ENVIADO",

    "ARQUIVO_SOLICITADO",
    "ARQUIVO_ENTREGUE",
    "ARQUIVO_FALHA"

} | EVENTOS_DEFENSIVOS | EVENTOS_MODO | EVENTOS_RESTAURACAO


# FUNÇÕES AUXILIARES

def contar_eventos_por_tipo(
    eventos,
    tipos_permitidos
):

    contador = Counter()

    for evento in eventos:

        tipo = evento.get(
            "tipo",
            ""
        )

        if tipo in tipos_permitidos:

            contador[tipo] += 1

    return contador


# TIMELINE RESUMIDA
def montar_timeline_resumida(
    timeline,
    limite=15
):

    eventos_resumidos = []


    for evento in timeline:

        origem = evento.get(
            "origem",
            ""
        )

        tipo = evento.get(
            "tipo",
            ""
        )

        ip = evento.get(
            "ip",
            ""
        )

        timestamp = evento.get(
            "timestamp",
            ""
        )


        # EVENTO DE SEGURANÇA
        if origem == "security":

            endpoint = evento.get(
                "endpoint",
                ""
            )

            args = evento.get(
                "args",
                ""
            )

            payload = evento.get(
                "payload",
                ""
            )


            resumo = endpoint


            if args:

                resumo += (
                    f" | args={args}"
                )


            if payload:

                if len(payload) > 120:

                    payload = (
                        payload[:120]
                        + "..."
                    )

                resumo += (
                    f" | payload={payload}"
                )


            eventos_resumidos.append(
                {
                    "timestamp": timestamp,
                    "origem": "security",
                    "tipo": tipo,
                    "ip": ip,
                    "resumo": resumo
                }
            )


        # EVENTO DE AUDITORIA
        elif origem == "audit":

            if tipo not in EVENTOS_AUDIT_RELEVANTES:
                continue


            detalhes = evento.get(
                "detalhes",
                ""
            )


            eventos_resumidos.append(
                {
                    "timestamp": timestamp,
                    "origem": "audit",
                    "tipo": tipo,
                    "ip": ip,
                    "resumo": detalhes
                }
            )


    return eventos_resumidos[-limite:]


# RESUMO AUTOMÁTICO
def gerar_resumo_automatico(dados):

    periodo = dados.get(
        "periodo",
        {}
    )

    totais = dados.get(
        "totais",
        {}
    )

    ataques = dados.get(
        "ataques",
        {}
    )

    ips = dados.get(
        "ips",
        {}
    )

    endpoints = dados.get(
        "endpoints",
        {}
    )

    defesas = dados.get(
        "defesas",
        {}
    )

    modos = dados.get(
        "modos",
        {}
    )


    inicio = periodo.get(
        "inicio"
    )

    fim = periodo.get(
        "fim"
    )

    total_eventos = totais.get(
        "eventos",
        0
    )

    total_audit = totais.get(
        "audit",
        0
    )

    total_security = totais.get(
        "security",
        0
    )

    total_ataques = totais.get(
        "ataques",
        0
    )

    total_defesas = totais.get(
        "defesas",
        0
    )

    total_eventos_modo = totais.get(
        "eventos_modo",
        0
    )


    paragrafos = []


    # PERÍODO E TOTAIS
    if inicio and fim:

        paragrafos.append(
            f"Durante o período de {inicio} a {fim}, "
            f"foram registrados {total_eventos} eventos "
            f"no ambiente CCTE, sendo {total_audit} eventos "
            f"de auditoria e {total_security} eventos "
            f"de segurança."
        )

    else:

        paragrafos.append(
            f"Foram registrados {total_eventos} eventos "
            f"no ambiente CCTE, sendo {total_audit} eventos "
            f"de auditoria e {total_security} eventos "
            f"de segurança."
        )


    # ATAQUES

    if ataques:

        quantidade_categorias = len(
            ataques
        )

        ataque_principal = max(
            ataques,
            key=ataques.get
        )

        quantidade_principal = ataques[
            ataque_principal
        ]

        paragrafos.append(
            f"Foram identificadas {total_ataques} "
            f"classificações de ataque distribuídas em "
            f"{quantidade_categorias} categorias. "
            f"A categoria mais recorrente foi "
            f"{ataque_principal}, com "
            f"{quantidade_principal} ocorrências."
        )

    else:

        paragrafos.append(
            "Nenhum ataque foi identificado durante "
            "o período analisado."
        )


    # ENDPOINTS
    if endpoints:

        endpoint_principal = max(
            endpoints,
            key=endpoints.get
        )

        quantidade_endpoint = endpoints[
            endpoint_principal
        ]

        paragrafos.append(
            f"O endpoint com maior número de eventos "
            f"de segurança foi {endpoint_principal}, "
            f"com {quantidade_endpoint} ocorrências."
        )


    # IPS
    if ips:

        if len(ips) == 1:

            ip = next(
                iter(ips)
            )

            quantidade_ip = ips[
                ip
            ]

            paragrafos.append(
                f"Os registros analisados apresentam "
                f"o endereço IP {ip}, associado a "
                f"{quantidade_ip} eventos."
            )

        else:

            ip_principal = max(
                ips,
                key=ips.get
            )

            quantidade_ip = ips[
                ip_principal
            ]

            paragrafos.append(
                f"Foram identificados {len(ips)} "
                f"endereços IP nos registros. "
                f"O endereço com maior quantidade "
                f"de eventos foi {ip_principal}, "
                f"com {quantidade_ip} ocorrências."
            )


    # DEFESA ATIVA
    if defesas:

        defesa_principal = max(
            defesas,
            key=defesas.get
        )

        quantidade_defesa = defesas[
            defesa_principal
        ]

        paragrafos.append(
            f"A camada de Defesa Ativa registrou "
            f"{total_defesas} eventos defensivos. "
            f"O evento defensivo mais recorrente foi "
            f"{defesa_principal}, com "
            f"{quantidade_defesa} ocorrências."
        )


    # MODO OPERACIONAL
    if modos:

        alteracoes = modos.get(
            "MODO_ALTERADO",
            0
        )

        paragrafos.append(
            f"Foram registrados "
            f"{total_eventos_modo} eventos relacionados "
            f"ao modo operacional do CCTE, incluindo "
            f"{alteracoes} alterações efetivas de modo."
        )


    return "\n\n".join(
        paragrafos
    )


# MONTAR DADOS DO RELATÓRIO
def montar_dados_relatorio():

    eventos_audit = carregar_audit()

    eventos_security = carregar_security()

    timeline = carregar_timeline()


    timeline_resumida = montar_timeline_resumida(
        timeline
    )


    ataques = contar_ataques()


    # CONTADOR DE IPS

    contador_ips = Counter()

    for evento in timeline:

        ip = evento.get(
            "ip"
        )

        if ip:

            contador_ips[ip] += 1


    # ENDPOINTS ATINGIDOS

    contador_endpoints = Counter()

    for evento in eventos_security:

        endpoint = evento.get(
            "endpoint"
        )

        if endpoint:

            contador_endpoints[
                endpoint
            ] += 1


    # EVENTOS DEFENSIVOS
    defesas = contar_eventos_por_tipo(
        eventos_audit,
        EVENTOS_DEFENSIVOS
    )


    # EVENTOS DE MODO
    modos = contar_eventos_por_tipo(
        eventos_audit,
        EVENTOS_MODO
    )


    # CONTADORES GERAIS

    total_audit = len(
        eventos_audit
    )

    total_security = len(
        eventos_security
    )

    total_eventos = (
        total_audit
        + total_security
    )

    total_ataques = sum(
        ataques.values()
    )

    total_defesas = sum(
        defesas.values()
    )

    total_eventos_modo = sum(
        modos.values()
    )


    # PERÍODO ANALISADO
    inicio_periodo = None

    fim_periodo = None


    if timeline:

        inicio_periodo = timeline[0].get(
            "timestamp"
        )

        fim_periodo = timeline[-1].get(
            "timestamp"
        )


    # ESTRUTURA DO RELATÓRIO
    dados = {

        "periodo": {
            "inicio": inicio_periodo,
            "fim": fim_periodo
        },

        "totais": {
            "audit": total_audit,
            "security": total_security,
            "eventos": total_eventos,
            "ataques": total_ataques,
            "defesas": total_defesas,
            "eventos_modo": total_eventos_modo
        },

        "ataques": dict(
            ataques
        ),

        "defesas": dict(
            defesas
        ),

        "modos": dict(
            modos
        ),

        "ips": dict(
            contador_ips
        ),

        "endpoints": dict(
            contador_endpoints
        ),

        "timeline": timeline_resumida
    }


    dados["resumo"] = gerar_resumo_automatico(
        dados
    )


    return dados


# GERAR RELATÓRIO EM TEXTO
def gerar_relatorio_texto(dados):

    linhas = []


    # CABEÇALHO

    linhas.append(
        "=" * 60
    )

    linhas.append(
        "RELATÓRIO FORENSE - CCTE"
    )

    linhas.append(
        "=" * 60
    )


    # PERÍODO ANALISADO

    linhas.append("")

    linhas.append(
        "PERÍODO ANALISADO"
    )

    linhas.append(
        f"Início: {dados['periodo']['inicio']}"
    )

    linhas.append(
        f"Fim: {dados['periodo']['fim']}"
    )


    # TOTAIS

    linhas.append("")

    linhas.append(
        "TOTAIS"
    )

    linhas.append(
        f"Eventos de auditoria: "
        f"{dados['totais']['audit']}"
    )

    linhas.append(
        f"Eventos de segurança: "
        f"{dados['totais']['security']}"
    )

    linhas.append(
        f"Total de eventos: "
        f"{dados['totais']['eventos']}"
    )

    linhas.append(
        f"Ataques classificados: "
        f"{dados['totais']['ataques']}"
    )

    linhas.append(
        f"Eventos defensivos: "
        f"{dados['totais']['defesas']}"
    )

    linhas.append(
        f"Eventos de modo operacional: "
        f"{dados['totais']['eventos_modo']}"
    )


    # RESUMO AUTOMÁTICO

    linhas.append("")

    linhas.append(
        "RESUMO AUTOMÁTICO"
    )

    linhas.append("")

    linhas.append(
        dados.get(
            "resumo",
            "Resumo não disponível."
        )
    )


    # ATAQUES POR CATEGORIA
    linhas.append("")

    linhas.append(
        "ATAQUES POR CATEGORIA"
    )


    if dados["ataques"]:

        for tipo, quantidade in dados[
            "ataques"
        ].items():

            linhas.append(
                f"{tipo}: {quantidade}"
            )

    else:

        linhas.append(
            "Nenhum ataque identificado."
        )


    # AÇÕES DEFENSIVAS
    linhas.append("")

    linhas.append(
        "AÇÕES DEFENSIVAS"
    )

    if dados["defesas"]:

        for tipo, quantidade in dados[
            "defesas"
        ].items():

            linhas.append(
                f"{tipo}: {quantidade}"
            )

    else:

        linhas.append(
            "Nenhuma ação defensiva registrada."
        )


    # MODO OPERACIONAL

    linhas.append("")

    linhas.append(
        "EVENTOS DE MODO OPERACIONAL"
    )

    if dados["modos"]:

        for tipo, quantidade in dados[
            "modos"
        ].items():

            linhas.append(
                f"{tipo}: {quantidade}"
            )

    else:

        linhas.append(
            "Nenhum evento de modo operacional registrado."
        )


    # IPS ENVOLVIDOS
    linhas.append("")

    linhas.append(
        "ENDEREÇOS IP ENVOLVIDOS"
    )


    if dados["ips"]:

        for ip, quantidade in dados[
            "ips"
        ].items():

            linhas.append(
                f"{ip}: {quantidade} eventos"
            )

    else:

        linhas.append(
            "Nenhum endereço IP identificado."
        )


    # ENDPOINTS ATINGIDOS
    linhas.append("")

    linhas.append(
        "ENDPOINTS ATINGIDOS"
    )


    if dados["endpoints"]:

        for endpoint, quantidade in dados[
            "endpoints"
        ].items():

            linhas.append(
                f"{endpoint}: {quantidade} eventos"
            )

    else:

        linhas.append(
            "Nenhum endpoint de segurança identificado."
        )


    # TIMELINE RESUMIDA
    linhas.append("")

    linhas.append(
        "TIMELINE RESUMIDA"
    )


    if dados["timeline"]:

        for evento in dados[
            "timeline"
        ]:

            linha = (
                f"{evento['timestamp']} | "
                f"{evento['origem'].upper()} | "
                f"{evento['tipo']} | "
                f"{evento['ip']} | "
                f"{evento['resumo']}"
            )

            linhas.append(
                linha
            )

    else:

        linhas.append(
            "Nenhum evento relevante identificado."
        )


    # FINAL
    linhas.append("")

    linhas.append(
        "=" * 60
    )

    linhas.append(
        "As classificações representam detecções realizadas "
        "pelo CCTE e não constituem, isoladamente, prova de "
        "comprometimento efetivo do sistema."
    )

    linhas.append(
        "=" * 60
    )


    return "\n".join(
        linhas
    )


# EXECUÇÃO DE TESTE
if __name__ == "__main__":

    dados = montar_dados_relatorio()


    print(
        "\nRELATÓRIO FORENSE - CCTE"
    )


    print(
        "\nPERÍODO ANALISADO"
    )

    print(
        "Início:",
        dados["periodo"]["inicio"]
    )

    print(
        "Fim:",
        dados["periodo"]["fim"]
    )


    print(
        "\nTOTAIS"
    )

    print(
        "Eventos de auditoria:",
        dados["totais"]["audit"]
    )

    print(
        "Eventos de segurança:",
        dados["totais"]["security"]
    )

    print(
        "Total de eventos:",
        dados["totais"]["eventos"]
    )

    print(
        "Ataques classificados:",
        dados["totais"]["ataques"]
    )

    print(
        "Eventos defensivos:",
        dados["totais"]["defesas"]
    )

    print(
        "Eventos de modo operacional:",
        dados["totais"]["eventos_modo"]
    )


    print(
        "\nATAQUES POR CATEGORIA"
    )

    if dados["ataques"]:

        for tipo, quantidade in dados[
            "ataques"
        ].items():

            print(
                f"{tipo}: {quantidade}"
            )

    else:

        print(
            "Nenhum ataque registrado."
        )


    print(
        "\nAÇÕES DEFENSIVAS"
    )

    if dados["defesas"]:

        for tipo, quantidade in dados[
            "defesas"
        ].items():

            print(
                f"{tipo}: {quantidade}"
            )

    else:

        print(
            "Nenhuma ação defensiva registrada."
        )


    print(
        "\nEVENTOS DE MODO OPERACIONAL"
    )

    if dados["modos"]:

        for tipo, quantidade in dados[
            "modos"
        ].items():

            print(
                f"{tipo}: {quantidade}"
            )

    else:

        print(
            "Nenhum evento de modo operacional registrado."
        )


    print(
        "\nIPS ENVOLVIDOS"
    )

    if dados["ips"]:

        for ip, quantidade in dados[
            "ips"
        ].items():

            print(
                f"{ip}: {quantidade} eventos"
            )

    else:

        print(
            "Nenhum endereço IP encontrado."
        )


    print(
        "\nENDPOINTS ATINGIDOS"
    )

    if dados["endpoints"]:

        for endpoint, quantidade in dados[
            "endpoints"
        ].items():

            print(
                f"{endpoint}: {quantidade} eventos"
            )

    else:

        print(
            "Nenhum endpoint de segurança encontrado."
        )


    print(
        "\nTIMELINE RESUMIDA"
    )

    if dados["timeline"]:

        for evento in dados[
            "timeline"
        ]:

            print(
                f"{evento['timestamp']} | "
                f"{evento['origem'].upper()} | "
                f"{evento['tipo']} | "
                f"{evento['ip']} | "
                f"{evento['resumo']}"
            )

    else:

        print(
            "Nenhum evento relevante encontrado."
        )


    print(
        "\nRESUMO AUTOMÁTICO"
    )

    print()

    print(
        dados["resumo"]
    )


    texto_relatorio = gerar_relatorio_texto(
        dados
    )


    print(
        "\nDOCUMENTO TEXTUAL"
    )

    print()

    print(
        texto_relatorio
    )