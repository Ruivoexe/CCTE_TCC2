from db import conectar
from vigilante import XSS, safe_str


#IDENTIFICAÇÃO DE XSS ARMAZENADO
def possui_xss(conteudo):

    conteudo_lower = safe_str(
        conteudo
    ).lower()

    for padrao in XSS:

        if padrao in conteudo_lower:
            return True

    return False


# LIMPEZA DE STORED XSS
def limpar_xss_armazenado():

    conexao = conectar()
    cursor = conexao.cursor()

    removidos = []

    try:

        # CARREGAR COMENTÁRIOS
        cursor.execute(
            "SELECT rowid, user, content "
            "FROM comentarios"
        )

        comentarios = cursor.fetchall()


        # ANALISAR COMENTÁRIOS
        for comentario in comentarios:

            comentario_id = comentario[0]
            usuario = comentario[1]
            conteudo = comentario[2]


            if possui_xss(conteudo):

                cursor.execute(
                    "DELETE FROM comentarios "
                    "WHERE rowid = ?",
                    (comentario_id,)
                )

                removidos.append(
                    {
                        "id": comentario_id,
                        "usuario": safe_str(usuario)
                    }
                )


        conexao.commit()


        return {
            "sucesso": True,
            "quantidade": len(removidos),
            "removidos": removidos
        }


    except Exception as erro:

        conexao.rollback()

        return {
            "sucesso": False,
            "quantidade": 0,
            "removidos": [],
            "erro": type(erro).__name__
        }


    finally:

        conexao.close()