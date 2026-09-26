import sqlite3

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    g,
    Response,
    make_response
)

from db import (
    conectar,
    iniciar_bd,
    apagar_bd
)

from audit import (
    audit,
    apagar_audit_log
)

from defesa_xss import limpar_xss_armazenado

from vigilante import (
    analisar_requisicao,
    registrar_resultado,
    limpar_tentativas_login,
    apagar_security_log
)

from forense.parse import (
    carregar_audit,
    carregar_security,
    carregar_timeline,
    contar_ataques
)

from forense.relatorio import (
    montar_dados_relatorio,
    gerar_relatorio_texto
)

from modo import (
    obter_modo,
    alterar_modo,
    descricao_modo,
    restaurar_modo_inicial,
    MODO_EDUCACIONAL,
    MODO_DEFESA_ATIVA
)

from defesa_bruteforce import (
    bloquear_ip,
    verificar_bloqueio,
    limpar_bloqueios
)


app = Flask(__name__)
app.secret_key = "chave"


# CONTEXTO GLOBAL
@app.context_processor
def contexto_global():

    return {
        "modo_atual_global": obter_modo()
    }


iniciar_bd()


# MONITORAMENTO DAS REQUISIÇÕES
@app.before_request
def monitorar():

    if request.path.startswith("/static"):
        return


    # VERIFICAR LIMITE DE REQUISIÇÕES ATIVO
    if (
        request.path == "/login"
        and request.method == "POST"
        and obter_modo() == MODO_DEFESA_ATIVA
    ):

        estado_bloqueio = verificar_bloqueio(
            request.remote_addr
        )

        if estado_bloqueio["bloqueado"]:

            tempo_restante = estado_bloqueio[
                "tempo_restante"
            ]

            audit(
                evento="DEFESA_REQUISICAO_LIMITADA",
                ip=request.remote_addr,
                detalhe=(
                    f"endpoint=/login "
                    f"tempo_restante={tempo_restante}"
                )
            )

            resposta = make_response(
                render_template(
                    "defesa_rate_limit.html",
                    tempo_restante=tempo_restante
                ),
                429
            )

            resposta.headers[
                "Retry-After"
            ] = str(
                tempo_restante
            )

            return resposta


    # ESTADO DA SESSÃO
    g.session_user_before = session.get(
        "user_id"
    )


    # CONSTRUÇÃO DO PAYLOAD
    partes = []

    if request.form:

        partes.append(
            str(request.form)
        )

    if request.args:

        partes.append(
            str(request.args)
        )

    partes.append(
        request.path
    )

    g.payload = " | ".join(
        partes
    )


    # ANÁLISE PREVENTIVA
    g.analise_seguranca = analisar_requisicao(
        ip=request.remote_addr,
        endpoint=request.path,
        payload=g.payload,
        args=request.args,
        session_user=g.session_user_before,
        method=request.method
    )


    # NENHUM ATAQUE DETECTADO
    if not g.analise_seguranca:
        return


    # VERIFICAR DECISÕES DEFENSIVAS

    for decisao in g.analise_seguranca.get(
        "decisoes",
        []
    ):


        # BLOQUEIO DE SQL INJECTION
        if (
            decisao.get("ataque") == "SQL INJECTION"
            and decisao.get("acao") == "BLOQUEAR_REQUISICAO"
            and decisao.get("mitigar") is True
        ):

            audit(
                evento="DEFESA_BLOQUEIO_APLICADO",
                ip=request.remote_addr,
                detalhe=(
                    f"ataque=SQL INJECTION "
                    f"endpoint={request.path} "
                    f"acao=BLOQUEAR_REQUISICAO"
                )
            )

            return render_template(
                "defesa_bloqueio.html",
                ataque="SQL Injection",
                acao="Bloqueio da requisição",
                endpoint=request.path,
                modo=decisao.get("modo")
            ), 403


        # BLOQUEIO DE IDOR
        if (
            decisao.get("ataque") == "IDOR"
            and decisao.get("acao") == "NEGAR_ACESSO"
            and decisao.get("mitigar") is True
        ):

            audit(
                evento="DEFESA_BLOQUEIO_APLICADO",
                ip=request.remote_addr,
                detalhe=(
                    f"ataque=IDOR "
                    f"endpoint={request.path} "
                    f"acao=NEGAR_ACESSO"
                )
            )

            return render_template(
                "defesa_bloqueio.html",
                ataque="IDOR",
                acao="Negação de acesso ao recurso",
                endpoint=request.path,
                modo=decisao.get("modo")
            ), 403


        # BLOQUEIO DE PATH TRAVERSAL
        if (
            decisao.get("ataque") == "PATH TRAVERSAL"
            and decisao.get("acao") == "BLOQUEAR_REQUISICAO"
            and decisao.get("mitigar") is True
        ):

            audit(
                evento="DEFESA_BLOQUEIO_APLICADO",
                ip=request.remote_addr,
                detalhe=(
                    f"ataque=PATH TRAVERSAL "
                    f"endpoint={request.path} "
                    f"acao=BLOQUEAR_REQUISICAO"
                )
            )

            return render_template(
                "defesa_bloqueio.html",
                ataque="Path Traversal",
                acao="Bloqueio da requisição de arquivo",
                endpoint=request.path,
                modo=decisao.get("modo")
            ), 403


        # BLOQUEIO DE FILE DISCLOSURE
        if (
            decisao.get("ataque") == "FILE DISCLOSURE"
            and decisao.get("acao") == "NEGAR_ARQUIVO"
            and decisao.get("mitigar") is True
        ):

            audit(
                evento="DEFESA_BLOQUEIO_APLICADO",
                ip=request.remote_addr,
                detalhe=(
                    f"ataque=FILE DISCLOSURE "
                    f"endpoint={request.path} "
                    f"acao=NEGAR_ARQUIVO"
                )
            )

            return render_template(
                "defesa_bloqueio.html",
                ataque="File Disclosure",
                acao="Negação de acesso ao arquivo sensível",
                endpoint=request.path,
                modo=decisao.get("modo")
            ), 403


        # BLOQUEIO DE XSS
        if (
            decisao.get("ataque") == "XSS"
            and decisao.get("acao") == "REJEITAR_CONTEUDO"
            and decisao.get("mitigar") is True
        ):

            audit(
                evento="DEFESA_BLOQUEIO_APLICADO",
                ip=request.remote_addr,
                detalhe=(
                    f"ataque=XSS "
                    f"endpoint={request.path} "
                    f"acao=REJEITAR_CONTEUDO"
                )
            )

            return render_template(
                "defesa_bloqueio.html",
                ataque="Cross-Site Scripting (XSS)",
                acao="Rejeição do conteúdo potencialmente malicioso",
                endpoint=request.path,
                modo=decisao.get("modo")
            ), 403


        # BLOQUEIO DE BRUTE FORCE
        if (
            decisao.get("ataque") == "BRUTEFORCE"
            and decisao.get("acao") == "LIMITAR_REQUISICOES"
            and decisao.get("mitigar") is True
        ):

            resultado_bloqueio = bloquear_ip(
                request.remote_addr
            )

            audit(
                evento="DEFESA_LIMITE_REQUISICOES_ATIVADO",
                ip=request.remote_addr,
                detalhe=(
                    f"ataque=BRUTEFORCE "
                    f"endpoint={request.path} "
                    f"duracao="
                    f"{resultado_bloqueio['duracao']}"
                )
            )

            resposta = make_response(
                render_template(
                    "defesa_rate_limit.html",
                    tempo_restante=resultado_bloqueio[
                        "duracao"
                    ]
                ),
                429
            )

            resposta.headers[
                "Retry-After"
            ] = str(
                resultado_bloqueio["duracao"]
            )

            return resposta


# REGISTRO APÓS A REQUISIÇÃO
@app.after_request
def analisar(response):

    if request.path.startswith("/static"):
        return response


    registrar_resultado(
        getattr(
            g,
            "analise_seguranca",
            None
        )
    )


    # EVITAR CACHE DURANTE OS EXERCÍCIOS
    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, max-age=0"
    )

    response.headers["Pragma"] = "no-cache"

    response.headers["Expires"] = "0"

    return response


# PÁGINA INICIAL
@app.route("/")
def home():

    return redirect(
        "/index"
    )


@app.route("/index")
def index():

    audit(
        evento="PAGINA_VISUALIZADA",
        ip=request.remote_addr,
        detalhe="endpoint=/index"
    )

    return render_template(
        "index.html"
    )


# REGISTRO VULNERÁVEL SQL INJECTION
@app.route(
    "/registro",
    methods=[
        "GET",
        "POST"
    ]
)
def registro():

    erro = None


    if request.method == "POST":

        username = (
            request.form.get("username")
            or ""
        ).strip()

        password = (
            request.form.get("password")
            or ""
        ).strip()


        if not username or not password:

            audit(
                evento="CAMPO_VAZIO",
                ip=request.remote_addr,
                detalhe=(
                    f"endpoint=/registro "
                    f"username_len={len(username)} "
                    f"password_len={len(password)}"
                )
            )

            erro = "Informe usuário e senha"

            return render_template(
                "registro.html",
                erro=erro
            )


        conexao = conectar()

        cursor = conexao.cursor()


        try:

            # SQL INJECTION PROPOSITAL
            cursor.execute(
                f"INSERT INTO users VALUES("
                f"NULL, '{username}', '{password}', 0)"
            )

            conexao.commit()


        except sqlite3.IntegrityError:

            conexao.rollback()

            audit(
                evento="USUARIO_DUPLICADO",
                ip=request.remote_addr,
                detalhe=f"username={username}"
            )

            erro = "Usuário já existe"

            return render_template(
                "registro.html",
                erro=erro
            )


        finally:

            conexao.close()


        audit(
            evento="USUARIO_CRIADO",
            ip=request.remote_addr,
            detalhe=f"username={username}"
        )


        return redirect(
            "/login"
        )


    return render_template(
        "registro.html",
        erro=erro
    )


# LOGIN VULNERÁVEL SQL INJECTION + BRUTE FORCE
@app.route(
    "/login",
    methods=[
        "GET",
        "POST"
    ]
)
def login():

    erro = None


    if request.method == "POST":

        username = (
            request.form.get("username")
            or ""
        ).strip()

        password = (
            request.form.get("password")
            or ""
        ).strip()


        if not username or not password:

            audit(
                evento="CAMPO_VAZIO",
                ip=request.remote_addr,
                detalhe=(
                    f"endpoint=/login "
                    f"username_len={len(username)} "
                    f"password_len={len(password)}"
                )
            )

            erro = "Informe usuário e senha"

            return render_template(
                "login.html",
                erro=erro
            )


        conexao = conectar()

        cursor = conexao.cursor()


        # SQL INJECTION PROPOSITAL
        query = (
            f"SELECT * FROM users "
            f"WHERE username = '{username}' "
            f"AND password = '{password}'"
        )


        print(
            "Query:",
            query
        )


        try:

            cursor.execute(
                query
            )

            resultado = cursor.fetchone()


        finally:

            conexao.close()


        if resultado:

            session["user_id"] = resultado[0]

            session["username"] = resultado[1]

            session["admin"] = resultado[3]


            audit(
                evento="LOGIN_SUCESSO",
                ip=request.remote_addr,
                detalhe=(
                    f"user_id={resultado[0]} "
                    f"username={resultado[1]}"
                )
            )


            return redirect(
                "/perfil"
            )


        audit(
            evento="LOGIN_FALHA",
            ip=request.remote_addr,
            detalhe=f"username={username}"
        )


        erro = "Usuário ou senha incorretos"


        return render_template(
            "login.html",
            erro=erro
        )


    return render_template(
        "login.html",
        erro=erro
    )


# LOGOUT

@app.route("/logout")
def logout():

    audit(
        evento="SESSAO_ENCERRADA",
        ip=request.remote_addr,
        detalhe=(
            f"user_id={session.get('user_id')} "
            f"username={session.get('username')}"
        )
    )


    session.clear()


    return redirect(
        "/login"
    )


# PERFIL VULNERÁVEL IDOR
@app.route("/perfil")
def perfil():

    if "user_id" not in session:

        audit(
            evento="PAGINA_BLOQUEADA_SEM_SESSAO",
            ip=request.remote_addr,
            detalhe="endpoint=/perfil"
        )


        return redirect(
            "/login"
        )


    session_id = session[
        "user_id"
    ]

    url_id = request.args.get(
        "id"
    )


    # IDOR PROPOSITAL

    user_id = (
        url_id
        if url_id
        else session_id
    )


    audit(
        evento="PAGINA_VISUALIZADA",
        ip=request.remote_addr,
        detalhe=(
            f"endpoint=/perfil "
            f"session_id={session_id} "
            f"requested_id={url_id}"
        )
    )


    conexao = conectar()

    cursor = conexao.cursor()


    query = (
        f"SELECT username, password, is_admin "
        f"FROM users "
        f"WHERE id = {user_id}"
    )


    print(
        "Query:",
        query
    )


    try:

        cursor.execute(
            query
        )

        user = cursor.fetchone()


    finally:

        conexao.close()


    if not user:

        return "Não encontrado", 404


    return render_template(
        "perfil.html",
        username=user[0],
        password=user[1],
        admin=user[2],
        user_id=user_id
    )


# COMENTÁRIOS
# STORED XSS PROPOSITAL

@app.route(
    "/comentarios",
    methods=[
        "GET",
        "POST"
    ]
)
def comentarios():

    audit(
        evento="PAGINA_VISUALIZADA",
        ip=request.remote_addr,
        detalhe=(
            f"endpoint=/comentarios "
            f"method={request.method}"
        )
    )


    conexao = conectar()

    cursor = conexao.cursor()


    try:

        if request.method == "POST":

            user = (
                request.form.get("user")
                or ""
            ).strip()

            content = (
                request.form.get("content")
                or ""
            )


            audit(
                evento="COMENTARIO_ENVIADO",
                ip=request.remote_addr,
                detalhe=(
                    f"user_field={user} "
                    f"len_content={len(content)}"
                )
            )


            cursor.execute(
                "INSERT INTO comentarios VALUES(NULL, ?, ?)",
                (
                    user,
                    content
                )
            )


            conexao.commit()


        cursor.execute(
            "SELECT user, content FROM comentarios"
        )


        dados = cursor.fetchall()


    finally:

        conexao.close()


    return render_template(
        "comentarios.html",
        dados=dados
    )


# DOWNLOAD VULNERÁVEL PATH TRAVERSAL + FILE DISCLOSURE
@app.route("/download")
def download():

    arquivo = (
        request.args.get("file")
        or ""
    ).strip()


    if not arquivo:

        audit(
            evento="PAGINA_VISUALIZADA",
            ip=request.remote_addr,
            detalhe="endpoint=/download"
        )


        return render_template(
            "download.html"
        )


    audit(
        evento="ARQUIVO_SOLICITADO",
        ip=request.remote_addr,
        detalhe=f"file={arquivo}"
    )


    try:

        # PATH TRAVERSAL / FILE DISCLOSURE PROPOSITAL

        with open(
            arquivo,
            "rb"
        ) as f:

            data = f.read()


        audit(
            evento="ARQUIVO_ENTREGUE",
            ip=request.remote_addr,
            detalhe=(
                f"file={arquivo} "
                f"bytes={len(data)}"
            )
        )


        return Response(
            data,
            mimetype="application/octet-stream"
        )


    except Exception as e:

        audit(
            evento="ARQUIVO_FALHA",
            ip=request.remote_addr,
            detalhe=(
                f"file={arquivo} "
                f"error={type(e).__name__}"
            )
        )


        return "Arquivo não encontrado", 404


# INTERFACE FORENSE DE AUDITORIA

@app.route("/forense/audit")
def forense_audit():

    eventos = carregar_audit()


    tipo_filtro = request.args.get(
        "tipo",
        ""
    ).strip()


    ip_filtro = request.args.get(
        "ip",
        ""
    ).strip()


    detalhes_filtro = request.args.get(
        "detalhes",
        ""
    ).strip()


    # FILTRO POR TIPO

    if tipo_filtro:

        eventos = [
            evento
            for evento in eventos
            if tipo_filtro.lower()
            in evento.get(
                "tipo",
                ""
            ).lower()
        ]


    # FILTRO POR IP

    if ip_filtro:

        eventos = [
            evento
            for evento in eventos
            if ip_filtro.lower()
            in evento.get(
                "ip",
                ""
            ).lower()
        ]


    # FILTRO POR DETALHES

    if detalhes_filtro:

        eventos = [
            evento
            for evento in eventos
            if detalhes_filtro.lower()
            in evento.get(
                "detalhes",
                ""
            ).lower()
        ]


    # EVENTOS MAIS RECENTES PRIMEIRO

    eventos.reverse()


    return render_template(
        "audit_logs.html",
        eventos=eventos,
        tipo_filtro=tipo_filtro,
        ip_filtro=ip_filtro,
        detalhes_filtro=detalhes_filtro
    )


# INTERFACE FORENSE DE SEGURANÇA
@app.route("/forense/security")
def forense_security():

    eventos = carregar_security()


    tipo_filtro = request.args.get(
        "tipo",
        ""
    ).strip()


    ip_filtro = request.args.get(
        "ip",
        ""
    ).strip()


    endpoint_filtro = request.args.get(
        "endpoint",
        ""
    ).strip()


    # FILTRO POR TIPO
    if tipo_filtro:

        eventos = [
            evento
            for evento in eventos
            if tipo_filtro.lower()
            in evento.get(
                "tipo",
                ""
            ).lower()
        ]


    # FILTRO POR IP

    if ip_filtro:

        eventos = [
            evento
            for evento in eventos
            if ip_filtro.lower()
            in evento.get(
                "ip",
                ""
            ).lower()
        ]


    # FILTRO POR ENDPOINT
    if endpoint_filtro:

        eventos = [
            evento
            for evento in eventos
            if endpoint_filtro.lower()
            in evento.get(
                "endpoint",
                ""
            ).lower()
        ]


    # EVENTOS MAIS RECENTES PRIMEIRO

    eventos.reverse()


    return render_template(
        "security_logs.html",
        eventos=eventos,
        tipo_filtro=tipo_filtro,
        ip_filtro=ip_filtro,
        endpoint_filtro=endpoint_filtro
    )


# PAINEL FORENSE
@app.route("/forense")
def forense():

    eventos_audit = carregar_audit()

    eventos_security = carregar_security()


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


    # ESTATÍSTICAS DOS ATAQUES

    ataques = contar_ataques()

    total_ataques = sum(
        ataques.values()
    )


    # TIMELINE FORENSE
    timeline = carregar_timeline()
    # EVENTOS MAIS RECENTES PRIMEIRO
    timeline.reverse()
    # ÚLTIMOS 10 EVENTOS
    ultimos_eventos = timeline[
        :10
    ]


    return render_template(
        "forense.html",
        total_audit=total_audit,
        total_security=total_security,
        total_eventos=total_eventos,
        total_ataques=total_ataques,
        ataques=ataques,
        ultimos_eventos=ultimos_eventos
    )


# RELATÓRIO FORENSE
@app.route("/forense/relatorio")
def forense_relatorio():

    dados = montar_dados_relatorio()


    return render_template(
        "relatorio.html",
        dados=dados
    )


# EXPORTAR RELATÓRIO FORENSE TXT
@app.route("/forense/relatorio/txt")
def exportar_relatorio_txt():

    dados = montar_dados_relatorio()


    texto = gerar_relatorio_texto(
        dados
    )


    return Response(
        texto,
        mimetype="text/plain; charset=utf-8",
        headers={
            "Content-Disposition":
            "attachment; "
            "filename=relatorio_forense_ccte.txt"
        }
    )


# MODO OPERACIONAL

@app.route(
    "/modo",
    methods=[
        "GET",
        "POST"
    ]
)
def visualizar_modo():

    # ALTERAÇÃO DO MODO
    if request.method == "POST":

        novo_modo = request.form.get(
            "modo"
        )


        resultado = alterar_modo(
            novo_modo
        )


        # ALTERAÇÃO VÁLIDA

        if resultado[
            "sucesso"
        ]:

            modo_anterior = resultado[
                "anterior"
            ]

            modo_atual = resultado[
                "atual"
            ]


            # MODO REALMENTE ALTERADO

            if modo_anterior != modo_atual:

                audit(
                    evento="MODO_ALTERADO",
                    ip=request.remote_addr,
                    detalhe=(
                        f"{modo_anterior} "
                        f"-> "
                        f"{modo_atual}"
                    )
                )


                # LIMPEZA DE XSS ARMAZENADO
                if modo_atual == MODO_DEFESA_ATIVA:

                    resultado_limpeza = (
                        limpar_xss_armazenado()
                    )


                    if resultado_limpeza[
                        "sucesso"
                    ]:

                        audit(
                            evento="DEFESA_LIMPEZA_XSS",
                            ip=request.remote_addr,
                            detalhe=(
                                f"comentarios_removidos="
                                f"{resultado_limpeza['quantidade']}"
                            )
                        )


                    else:

                        audit(
                            evento="DEFESA_LIMPEZA_XSS_FALHA",
                            ip=request.remote_addr,
                            detalhe=(
                                f"erro="
                                f"{resultado_limpeza.get('erro')}"
                            )
                        )


            # MESMO MODO SOLICITADO
            else:

                audit(
                    evento="MODO_MANTIDO",
                    ip=request.remote_addr,
                    detalhe=(
                        f"modo={modo_atual}"
                    )
                )


        # MODO INVÁLIDO
        else:

            audit(
                evento="MODO_INVALIDO",
                ip=request.remote_addr,
                detalhe=(
                    f"modo_solicitado={novo_modo}"
                )
            )


        return redirect(
            "/modo"
        )


    # VISUALIZAÇÃO DA PÁGINA
    modo_atual = obter_modo()


    audit(
        evento="PAGINA_VISUALIZADA",
        ip=request.remote_addr,
        detalhe=(
            f"endpoint=/modo "
            f"modo_atual={modo_atual}"
        )
    )


    return render_template(
        "modo.html",
        modo_atual=modo_atual,
        descricao_atual=descricao_modo(),
        modo_educacional=MODO_EDUCACIONAL,
        modo_defesa_ativa=MODO_DEFESA_ATIVA,
        descricao_educacional=descricao_modo(
            MODO_EDUCACIONAL
        ),
        descricao_defesa=descricao_modo(
            MODO_DEFESA_ATIVA
        )
    )


# RESTAURAÇÃO DO AMBIENTE
@app.route(
    "/reset",
    methods=[
        "GET",
        "POST"
    ]
)
def reset_ambiente():

    # EXIBIR PÁGINA DE CONFIRMAÇÃO
    if request.method == "GET":

        return render_template(
            "reset.html",
            restaurado=False,
            erro=None
        )


    # CONFIRMAÇÃO DA OPERAÇÃO
    confirmacao = (
        request.form.get(
            "confirmacao"
        )
        or ""
    ).strip().upper()


    if confirmacao != "RESETAR":

        return render_template(
            "reset.html",
            restaurado=False,
            erro=(
                "Confirmação inválida. "
                "Digite RESETAR para executar a restauração."
            )
        ), 400


    # IP RESPONSÁVEL PELA RESTAURAÇÃO
    ip = request.remote_addr


    try:

        # LIMPAR TENTATIVAS DE LOGIN
        tentativas_removidas = (
            limpar_tentativas_login()
        )
        # LIMPAR BLOQUEIOS TEMPORÁRIOS
        bloqueios_removidos = (
            limpar_bloqueios()
        )
        #RESTAURAR MODO EDUCACIONAL
        restaurar_modo_inicial()
        #ENCERRAR SESSÃO ATUAL
        session.clear()
        # APAGAR BANCO DE DADOS
        banco_apagado = apagar_bd()
        # RECRIAR BANCO DE DADOS
        iniciar_bd()
        #APAGAR SECURITY.LOG
        security_apagado = (
            apagar_security_log()
        )
        # APAGAR AUDIT.LOG
        audit_apagado = (
            apagar_audit_log()
        )
        # REGISTRAR INÍCIO DA NOVA SESSÃO

        audit(
            evento="AMBIENTE_RESTAURADO",
            ip=ip,
            detalhe=(
                f"database_apagado={banco_apagado} "
                f"database_recriado=True "
                f"audit_anterior_apagado={audit_apagado} "
                f"security_anterior_apagado={security_apagado} "
                f"tentativas_removidas={tentativas_removidas} "
                f"bloqueios_removidos={bloqueios_removidos} "
                f"modo={obter_modo()}"
            )
        )


        return render_template(
            "reset.html",
            restaurado=True,
            erro=None,
            banco_apagado=banco_apagado,
            audit_apagado=audit_apagado,
            security_apagado=security_apagado,
            tentativas_removidas=tentativas_removidas,
            bloqueios_removidos=bloqueios_removidos,
            modo_atual=obter_modo()
        )


    except Exception as erro_reset:

        audit(
            evento="AMBIENTE_RESTAURACAO_FALHA",
            ip=ip,
            detalhe=(
                f"erro="
                f"{type(erro_reset).__name__}"
            )
        )


        return render_template(
            "reset.html",
            restaurado=False,
            erro=(
                "Não foi possível concluir "
                "a restauração do ambiente."
            )
        ), 500

#INICIAR

if __name__ == "__main__":

    app.run(
        debug=True
    )