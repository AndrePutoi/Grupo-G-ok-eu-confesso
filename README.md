# OK-Eu-CONFESSO 📧🔒
> Sistema de recibo de leitura com garantia criptográfica

## O que é?
Sistema web que garante que o destinatário de um email realmente leu a mensagem. O corpo do email é cifrado e só pode ser decifrado após o destinatário confirmar explicitamente a receção e leitura, gerando um recibo assinado digitalmente.

## Requisitos
- Python 3.10+
- pip

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

**5. Corre a aplicação**
```bash
python run.py
```

**6. Abre o browser em**
```
http://localhost:5000
```

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
│   │   └── dashboard.html
│   └── static/              ← CSS, JS, imagens
│       └── style.css
├── config.py                ← configurações gerais
├── .env                     ← variáveis secretas (não vai para o git)
├── requirements.txt
└── run.py                   ← ponto de entrada
```

---

## Divisão de tarefas

| Pessoa | Responsabilidade |
|--------|-----------------|
| Pessoa 1 | Setup, autenticação, base de dados, integração |
| Pessoa 2 | Chaves RSA, assinaturas digitais (`crypto/rsa_keys.py`) |
| Pessoa 3 | Cifra AES, códigos, PBKDF2 (`crypto/aes_email.py`) |
| Pessoa 4 | Envio de emails, lógica do destinatário (`routes/sender.py`, `routes/receiver.py`) |
| Pessoa 5 | Frontend, recibos, verificação (`templates/`, `static/`) |

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
