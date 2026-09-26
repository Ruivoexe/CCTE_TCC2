# CCTE - Cyber Campo de Treinamento Educacional

## Sobre o projeto

O CCTE (Cyber Campo de Treinamento Educacional) é um ambiente web educacional voltado ao ensino prático de cibersegurança.

O projeto foi desenvolvido como um cyber range web de execução local, contendo vulnerabilidades implementadas intencionalmente para permitir a observação controlada do ciclo de um incidente:

Tentativa -> Detecção -> Registro -> Análise -> Resposta

O sistema permite explorar vulnerabilidades, acompanhar eventos de auditoria e segurança, comparar diferentes modos operacionais e analisar os resultados por meio de recursos forenses.

O CCTE é um projeto acadêmico desenvolvido no curso de Análise e Desenvolvimento de Sistemas do Instituto Federal de Educação, Ciência e Tecnologia Farroupilha - Campus Alegrete.

## Aviso de segurança

Este projeto contém vulnerabilidades implementadas propositalmente para fins educacionais.

O CCTE deve ser executado somente em ambiente local, controlado e autorizado.

Não é recomendado publicar a aplicação diretamente na Internet.

Não utilize os exemplos, técnicas ou scripts do projeto contra sistemas, aplicações, redes ou serviços de terceiros sem autorização.

Os dados utilizados no laboratório devem ser fictícios. Não utilize senhas reais, informações pessoais, credenciais institucionais, dados bancários ou qualquer informação sensível.

## Objetivo

O objetivo do CCTE é disponibilizar um ambiente acessível para treinamento prático em segurança de aplicações web, permitindo estudar:

- vulnerabilidades web;
- comportamento de requisições suspeitas;
- monitoramento;
- detecção;
- auditoria;
- resposta defensiva;
- análise forense;
- geração de relatórios técnicos.

O projeto busca demonstrar não apenas a exploração de vulnerabilidades, mas o ciclo completo de um incidente dentro de um laboratório controlado.

## Tecnologias utilizadas

- Python 3.13
- Flask
- SQLite
- HTML5
- CSS3
- Jinja2
- Requests
- PyCharm

Bibliotecas da biblioteca padrão do Python, como sqlite3, os, datetime e collections, não precisam ser instaladas separadamente.

## Funcionalidades

O CCTE possui atualmente:

- cadastro de usuários;
- login;
- logout;
- perfil de usuário;
- sistema de comentários;
- área de downloads;
- alternância de modo operacional;
- monitoramento de requisições;
- detecção de comportamentos suspeitos;
- Audit Log;
- Security Log;
- mecanismos de Defesa Ativa;
- detecção de Brute Force;
- limitação temporária de requisições;
- bloqueio temporário;
- tratamento defensivo de XSS;
- painel forense;
- relatório forense;
- exportação do relatório em TXT;
- restauração do ambiente;
- simulador de requisições para testes controlados.

## Vulnerabilidades educacionais

As vulnerabilidades existentes no projeto são intencionais e fazem parte do laboratório.

Principais categorias:

- SQL Injection - login e cadastro;
- Brute Force - login;
- IDOR - perfil;
- Stored XSS - comentários;
- Path Traversal - downloads;
- File Disclosure - downloads.

Essas vulnerabilidades não representam boas práticas de desenvolvimento. Elas permanecem no sistema para permitir exploração, detecção, registro e comparação entre diferentes comportamentos defensivos.

## Modos operacionais

### Modo Educacional

No Modo Educacional, as vulnerabilidades permanecem exploráveis.

O sistema continua executando:

- monitoramento;
- detecção;
- geração de logs;
- análise forense;
- geração de relatório.

As principais medidas automáticas de mitigação não impedem a exploração.

Esse modo permite observar como uma requisição suspeita se comporta quando alcança uma implementação vulnerável.

### Defesa Ativa

No modo Defesa Ativa, o sistema mantém o monitoramento e também pode aplicar respostas automáticas.

Entre as respostas implementadas estão:

- bloqueio de requisições;
- restrição de acesso;
- rejeição de conteúdo;
- limitação temporária de requisições;
- bloqueio temporário relacionado a Brute Force;
- tratamento defensivo de conteúdo XSS armazenado.

A vulnerabilidade continua existindo no laboratório, mas a aplicação passa a demonstrar mecanismos de mitigação.

### Persistência do modo

O modo operacional é mantido somente enquanto a aplicação está em execução.

Ao encerrar e iniciar novamente o servidor, o CCTE retorna ao modo:

EDUCACIONAL

A função de restauração do ambiente também redefine o sistema para o Modo Educacional.

## Logs

O CCTE utiliza dois arquivos principais de log.

### Audit Log

Arquivo:

logs/audit.log

Registra eventos operacionais da aplicação, incluindo:

- visualização de páginas;
- login;
- falha de login;
- criação de usuário;
- encerramento de sessão;
- envio de comentários;
- operações de download;
- alterações de modo;
- ações defensivas;
- restauração do ambiente.

### Security Log

Arquivo:

logs/security.log

Registra requisições classificadas como suspeitas ou potencialmente maliciosas, incluindo:

- SQL Injection;
- XSS;
- IDOR;
- Path Traversal;
- File Disclosure;
- Brute Force.

A presença de um evento no Security Log representa uma detecção realizada pelo CCTE.

Uma detecção não significa necessariamente que a tentativa foi bloqueada.

No Modo Educacional, uma requisição pode ser detectada, registrada e ainda alcançar a funcionalidade vulnerável.

## Análise forense

O módulo forense processa os registros presentes em:

logs/audit.log
logs/security.log

A interface permite consultar:

- eventos de auditoria;
- eventos de segurança;
- categorias de ataque;
- endereços IP;
- endpoints;
- ações defensivas;
- alterações de modo;
- timeline de eventos;
- resumo consolidado.

O relatório forense pode ser visualizado pela interface e exportado em formato TXT.

## Restauração do ambiente

O CCTE possui uma função de restauração destinada a preparar o laboratório para uma nova sessão.

A restauração:

- limpa tentativas temporárias de Brute Force;
- remove bloqueios temporários;
- redefine o modo para Educacional;
- encerra a sessão atual;
- remove e recria o banco de dados;
- remove os logs anteriores;
- recria o estado inicial da aplicação.

Após a restauração, um novo Audit Log é iniciado.

Importante:

A restauração remove os registros da sessão anterior. Caso seja necessário preservar os resultados, exporte o relatório forense antes de restaurar o ambiente.

## Estrutura do projeto

ccte-master/

    README.md
    requirements.txt

    files/
        README.md
        tcc1.pdf
        tcc2.pdf
        users.txt

    forense/
        __init__.py
        parse.py
        relatorio.py

    logs/
        audit.log
        security.log

    static/
        style.css

    templates/
        audit_logs.html
        comentarios.html
        defesa_bloqueio.html
        defesa_rate_limit.html
        download.html
        forense.html
        index.html
        login.html
        modo.html
        perfil.html
        registro.html
        relatorio.html
        reset.html
        security_logs.html

    app.py
    audit.py
    config.py
    database.db
    db.py
    defesa_ativa.py
    defesa_bruteforce.py
    defesa_xss.py
    modo.py
    simulador.py
    vigilante.py

## Diretório files

O diretório files contém os arquivos utilizados pela funcionalidade de downloads e pelos exercícios relacionados a File Disclosure e Path Traversal.

Arquivos apresentados normalmente pela interface:

- files/README.md
- files/tcc1.pdf
- files/tcc2.pdf

Arquivo mantido propositalmente fora da listagem normal:

- files/users.txt

O arquivo users.txt permanece disponível fisicamente no diretório para permitir exercícios controlados de File Disclosure.

## Banco de dados

O projeto utiliza SQLite.

Arquivo:

database.db

O banco armazena o estado atual da aplicação, incluindo usuários e comentários.

O arquivo pode ser removido pela função de restauração e recriado automaticamente pelo módulo de banco de dados.

Como o CCTE é um ambiente propositalmente vulnerável, algumas implementações presentes no banco e nas rotas não representam práticas recomendadas para sistemas reais.

## Pré-requisitos

Para executar o projeto é necessário:

- Python 3.13;
- pip;
- navegador web moderno.

O PyCharm é opcional.

Para verificar a versão do Python:

python --version

No Windows, também pode ser utilizado:

py --version

Resultado esperado:

Python 3.13.x

## Instalação

### 1. Obter o projeto

Baixe ou copie o diretório do CCTE para o computador.

Exemplo:

C:\Projetos\ccte-master

Abra um terminal dentro da pasta raiz do projeto.

A pasta correta é aquela que contém o arquivo:

app.py

### 2. Criar ambiente virtual

Windows:

python -m venv .venv

ou:

py -m venv .venv

Linux/macOS:

python3 -m venv .venv

### 3. Ativar o ambiente virtual

Windows - Prompt de Comando:

.venv\Scripts\activate

Windows - PowerShell:

.\.venv\Scripts\Activate.ps1

Linux/macOS:

source .venv/bin/activate

### 4. Atualizar o pip

python -m pip install --upgrade pip

### 5. Instalar as dependências

python -m pip install -r requirements.txt

## requirements.txt

O arquivo requirements.txt deve conter as dependências externas utilizadas pelo projeto.

Conteúdo recomendado:

Flask>=3.1,<4.0
requests>=2.32,<3.0

Flask é utilizado pela aplicação web.

Requests é utilizado pelo simulador de requisições.

## Inicialização pelo terminal

Com o ambiente virtual ativado e o terminal aberto na pasta que contém app.py, execute:

python app.py

No Windows, também pode ser utilizado:

py app.py

O Flask deverá iniciar o servidor local.

Normalmente será exibido um endereço semelhante a:

http://127.0.0.1:5000

Mantenha o terminal aberto enquanto estiver utilizando o sistema.

## Abrindo o sistema no navegador

Depois de iniciar app.py, abra o navegador e acesse:

http://localhost:5000/index

Também pode ser utilizado:

http://127.0.0.1:5000/index

A rota:

http://localhost:5000/

redireciona para a página inicial do CCTE.

localhost representa o próprio computador no qual o servidor Flask está sendo executado.

## Execução pelo PyCharm

1. Abra o PyCharm.
2. Selecione Open.
3. Abra a pasta ccte-master.
4. Configure um interpretador Python 3.13.
5. Preferencialmente utilize o ambiente virtual .venv.
6. Instale as dependências de requirements.txt.
7. Abra app.py.
8. Execute app.py utilizando Run.
9. Aguarde a inicialização do servidor Flask.
10. Abra o navegador.
11. Acesse:

http://localhost:5000/index

## Primeira inicialização

Durante a inicialização, o módulo de banco de dados prepara a estrutura necessária para o funcionamento do sistema.

Caso o banco de dados não exista, ele pode ser criado novamente pela aplicação.

A estrutura de diretórios do projeto deve ser preservada.

## Rotas principais

/  
Redireciona para a página inicial.

/index  
Página inicial do CCTE.

/login  
Login.

/registro  
Cadastro de usuário.

/perfil  
Perfil do usuário.

/comentarios  
Área de comentários.

/download  
Área de downloads.

/modo  
Seleção do modo operacional.

/forense  
Painel forense.

/forense/audit  
Visualização do Audit Log.

/forense/security  
Visualização do Security Log.

/forense/relatorio  
Relatório forense.

/forense/relatorio/txt  
Exportação do relatório em TXT.

/reset  
Restauração do ambiente.

/logout  
Encerramento da sessão.

## Arquivos principais

### app.py

Aplicação principal Flask.

Responsável pelas rotas, sessões, integração dos módulos e funcionamento geral da aplicação web.

### db.py

Responsável pela conexão com SQLite, inicialização do banco e suporte à restauração.

### audit.py

Responsável pela geração do Audit Log.

### vigilante.py

Responsável pelo monitoramento e classificação de requisições suspeitas.

### defesa_ativa.py

Responsável pelas decisões e respostas utilizadas no modo Defesa Ativa.

### defesa_bruteforce.py

Responsável pelo controle de tentativas, limitação temporária e bloqueios relacionados a Brute Force.

### defesa_xss.py

Responsável pelos mecanismos defensivos relacionados a XSS armazenado.

### modo.py

Responsável pelo gerenciamento dos modos operacionais.

### forense/parse.py

Responsável pela leitura e processamento dos arquivos de log.

### forense/relatorio.py

Responsável pela consolidação dos dados e geração do relatório técnico.

### simulador.py

Utilizado para executar requisições automatizadas contra o próprio laboratório.

O simulador deve ser utilizado somente contra uma instância local e autorizada do CCTE.

## Fluxo sugerido para uma atividade

Uma sessão prática pode seguir esta sequência:

1. Iniciar a aplicação.
2. Abrir /index.
3. Utilizar o Modo Educacional.
4. Executar um exercício vulnerável.
5. Observar o comportamento da aplicação.
6. Consultar o Security Log.
7. Consultar o Audit Log.
8. Abrir o Painel Forense.
9. Consultar ou exportar o relatório.
10. Ativar a Defesa Ativa.
11. Repetir o mesmo exercício.
12. Comparar os resultados.
13. Exportar o relatório TXT, se necessário.
14. Restaurar o ambiente.

Esse fluxo permite comparar a exploração sem mitigação automática com o comportamento da mesma tentativa diante dos mecanismos defensivos.

## Downloads e exercícios de arquivos

Arquivos legítimos apresentados pela interface:

files/README.md
files/tcc1.pdf
files/tcc2.pdf

Exemplo de arquivo existente, mas oculto da interface:

files/users.txt

Isso permite diferenciar didaticamente:

Download legítimo:
arquivo apresentado normalmente pela interface.

File Disclosure:
arquivo existente, mas não apresentado como recurso normal ao usuário.

Path Traversal:
tentativa de navegar para fora do diretório esperado utilizando elementos como ../

## Uso educacional

O CCTE foi projetado para:

- aulas;
- demonstrações;
- atividades acadêmicas;
- treinamento local;
- estudo de vulnerabilidades;
- análise de logs;
- comparação entre detecção e mitigação.

O projeto não foi desenvolvido para:

- hospedagem pública;
- armazenamento de dados reais;
- autenticação de produção;
- processamento de dados sensíveis;
- proteção de sistemas reais.

## Publicação no GitHub

Antes de publicar o projeto, recomenda-se utilizar um arquivo .gitignore para evitar o versionamento de arquivos temporários e dados gerados durante a execução.

Exemplo:

.venv/
__pycache__/
.idea/
*.pyc
database.db
logs/*.log

O README.md principal deve permanecer na raiz do repositório para ser exibido automaticamente pelo GitHub.

A cópia existente em files/README.md faz parte dos arquivos disponibilizados pelo próprio laboratório.

## Estado atual

O CCTE possui implementados:

- ambiente vulnerável;
- monitoramento;
- Audit Log;
- Security Log;
- modos operacionais;
- Defesa Ativa;
- Brute Force e limitação temporária;
- defesa relacionada a XSS;
- análise forense;
- relatório forense;
- exportação TXT;
- restauração do ambiente;
- interface web;
- documentação básica de instalação e execução.

O projeto permanece sujeito a revisões de código, testes finais e ajustes necessários para a versão acadêmica definitiva.

## Instituição

Instituto Federal de Educação, Ciência e Tecnologia Farroupilha  
Campus Alegrete

Curso: Análise e Desenvolvimento de Sistemas

Ano: 2026

## Créditos acadêmicos

Projeto: CCTE - Cyber Campo de Treinamento Educacional

Professor(a) orientador(a): Josiane Fontoura

Coordenador do curso: Marcelo Rosa

## Licença

A licença do projeto ainda não foi definida.

Antes da publicação definitiva do repositório, recomenda-se selecionar uma licença compatível com os objetivos acadêmicos e educacionais do CCTE.
