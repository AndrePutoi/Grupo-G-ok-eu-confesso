# OK-Eu-CONFESSO 📧🔒
> Sistema de recibo de leitura com garantia criptográfica

## O que é?
Sistema web que garante que o destinatário de um email realmente leu a mensagem. O corpo do email é cifrado e só pode ser decifrado após o destinatário confirmar explicitamente a receção e leitura, gerando um recibo assinado digitalmente.

## Requisitos
- Python 3.10+
- pip
- MailHog (servidor SMTP local para testes)

## Instalação do MailHog

O MailHog simula um servidor de e-mail localmente — os e-mails enviados pela aplicação aparecem numa interface web em vez de serem enviados de verdade.

**Windows:**
1. Descarrega o executável `MailHog_windows_amd64.exe` de https://github.com/mailhog/MailHog/releases
2. Coloca-o na raiz do projeto (não é enviado para o GitHub e está listado no .gitignore)

**Mac:**
```bash
brew install mailhog
```

**Linux:**
```bash
sudo apt install mailhog
# ou
go install github.com/mailhog/MailHog@latest
```

## Como correr o projeto

**1. Clona o repositório**
```bash
git clone https://github.com/AndrePutoi/Grupo-G-ok-eu-confesso.git
cd Grupo-G-ok-eu-confesso
```

**2. Cria e ativa o ambiente virtual**
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate
```

**3. Instala as dependências**
```bash
pip install -r requirements.txt
```

**4. Cria o ficheiro `.env` na raiz**
```
SECRET_KEY=coloca-aqui-uma-chave-aleatoria-de-32-chars
DATABASE_URL=sqlite:///okeuconfesso.db
```

Para gerar a SECRET_KEY:
```python
import secrets
print(secrets.token_hex(32))
```

> As variáveis `MAIL_HOST`, `MAIL_PORT`, `MAIL_FROM` e `SYSTEM_URL` são opcionais — os valores por defeito funcionam para execução local com MailHog.

**5. Arranca o MailHog** (numa janela separada)

Windows:
```bash
.\MailHog_windows_amd64.exe
```

Mac/Linux:
```bash
mailhog
```

**6. Arranca a aplicação** (noutra janela)
```bash
python run.py
```

**7. Abre o browser**

| URL | Descrição |
|-----|-----------|
| http://localhost:5000 | Aplicação web |
| http://localhost:8025 | Interface do MailHog (e-mails enviados) |

---

## Estrutura do projeto

```
ok-eu-confesso/
├── app/
│   ├── __init__.py          ← configuração da app Flask
│   ├── routes/
│   │   ├── auth.py          ← registo e login
│   │   ├── sender.py        ← envio de emails
│   │   └── receiver.py      ← receção e decifra
│   ├── models/
│   │   └── models.py        ← tabelas da base de dados
│   ├── crypto/
│   │   ├── rsa_keys.py      ← geração de chaves RSA e assinaturas
│   │   └── aes_email.py     ← cifra e decifra do email
│   ├── templates/           ← páginas HTML
│   │   ├── login.html
│   │   ├── register.html
│   │   ├── dashboard.html
│   │   ├── receipt.html
│   │   ├── sender/
│   │   │   └── send.html
│   │   └── receiver/
│   │       ├── receive.html
│   │       └── verify.html
│   └── static/              ← CSS, JS, imagens
│       └── style.css
├── config.py                ← configurações gerais
├── .gitignore               ← ficheiros locais ignorados pelo Git
├── .env                     ← variáveis secretas (não vai para o git)
├── requirements.txt
└── run.py                   ← ponto de entrada
```

---

## Divisão de tarefas

| Pessoa          | Responsabilidade |
|-----------------|-----------------|
| André Putoi     | Setup, autenticação, base de dados, integração |
| Angelina Santos | Chaves RSA, assinaturas digitais (`crypto/rsa_keys.py`) |
| João Craveiro   | Cifra AES, códigos, PBKDF2 (`crypto/aes_email.py`) |
| Patrícia Marcos | Envio de emails, lógica do destinatário (`routes/sender.py`, `routes/receiver.py`) |
| Carolina Raposo | Frontend, recibos, verificação (`templates/`, `static/`) |

---

## Fluxo do sistema

1. Emissor regista-se → recebe password de 16 chars gerada pelo sistema
2. Emissor envia email → corpo cifrado com AES-256-CTR + código gerado aleatoriamente
3. Destinatário recebe email cifrado + link + código
4. Destinatário acede ao site, fornece o código e confirma receção e leitura
5. Sistema decifra o email e gera recibo assinado digitalmente
6. Emissor pode verificar o recibo e validar a assinatura

---

## Tecnologias utilizadas

- **Flask** — framework web
- **SQLAlchemy** — base de dados (SQLite)
- **Flask-Login** — gestão de sessões
- **argon2** — hash seguro de passwords
- **cryptography** — AES, RSA, PBKDF2
