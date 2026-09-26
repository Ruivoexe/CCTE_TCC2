import os
import sqlite3

#CAMINHOS DO PROJETO
BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DB_PATH = os.path.join(
    BASE_DIR,
    "database.db"
)

LOG_DIR = os.path.join(
    BASE_DIR,
    "logs"
)

#USUÁRIOS PADRÃO

USUARIOS_PADRAO = [
    ("ana", "123456", 0),
    ("carlos", "qwerty", 0),
    ("joao", "admin123", 0),
    ("maria", "senha123", 0),
    ("admin", "admin", 1),
    ("sysadmin", "SuperSecure123", 1),
]


#CONEXÃO
def conectar():

    return sqlite3.connect(
        DB_PATH
    )


# APAGAR BANCO
def apagar_bd():

    if not os.path.exists(
        DB_PATH
    ):

        return False

    os.remove(
        DB_PATH
    )

    return True


#INICIALIZAÇÃO
def iniciar_bd():

    os.makedirs(
        LOG_DIR,
        exist_ok=True
    )

    conexao = conectar()

    try:

        cursor = conexao.cursor()


        # TABELA DE USUÁRIOS
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                password TEXT,
                is_admin INTEGER
            )
            """
        )


        # IMPEDIR USERNAMES DUPLICADOS
        cursor.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username
            ON users(username)
            """
        )

        # TABELA DE COMENTÁRIOS
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS comentarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT,
                content TEXT
            )
            """
        )

        # USUÁRIOS PADRÃO
        cursor.execute(
            "SELECT COUNT(*) FROM users"
        )

        total = cursor.fetchone()[0]

        if total == 0:

            print(
                "[+] Criando usuários padrão"
            )

            cursor.executemany(
                """
                INSERT INTO users(
                    username,
                    password,
                    is_admin
                )
                VALUES (?, ?, ?)
                """,
                USUARIOS_PADRAO
            )

        else:

            print(
                "[+] Usuários padrão já existentes"
            )


        conexao.commit()


    finally:

        conexao.close()

if __name__ == "__main__":

    print(
        "Banco:",
        DB_PATH
    )

    print(
        "Existe:",
        os.path.exists(DB_PATH)
    )