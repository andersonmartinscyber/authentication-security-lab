# Laboratório de Segurança de Autenticação com Kali Linux e Medusa

**Autor:** Anderson Martins dos Santos

**Bootcamp:** Santander — Cibersegurança do Zero à Prática — DIO

**Desafio:** Simulando um Ataque de Brute Force de Senhas com Medusa e Kali Linux

**Data dos testes:** 14/11/2026

## Objetivo

Demonstrar testes de dicionário em FTP e formulário web, além de enumeração e password spraying em SMB. Os resultados foram validados com clientes independentes e relacionados a medidas de prevenção.

## Escopo e ambiente

Os testes foram direcionados exclusivamente à VM Metasploitable 2 do laboratório do autor, no endereço `192.168.2.98`.

| Componente | Configuração observada |
|---|---|
| Máquina de auditoria | Computador dedicado com Kali Linux |
| Sistema | Kali GNU/Linux Rolling 2026.3 |
| Kernel | 7.2.15+kali-amd64 |
| IP do Kali | 192.168.2.33 |
| Interface do Kali | wlan0 |
| Alvo | Metasploitable 2 no VirtualBox |
| IP do alvo | 192.168.2.98/24 |
| Interface do alvo | eth0 |
| Aplicação web | DVWA 1.0.7, segurança Low |
| Medusa | 2.3 |
| Nmap | 7.991 |

O ambiente foi adaptado: o Kali foi executado em um computador físico, em vez de uma segunda VM. A conectividade foi comprovada. O modo de rede do VirtualBox e seu isolamento não foram registrados nas evidências disponíveis.

As credenciais documentadas pertencem ao ambiente vulnerável de laboratório.

## Conceitos aplicados

- **Força bruta:** tentativa sistemática de combinações de credenciais.
- **Ataque de dicionário:** teste de senhas presentes em uma lista.
- **Password spraying:** teste de uma mesma senha contra várias contas.
- **Enumeração:** identificação de informações expostas por um serviço.

Os cenários FTP e DVWA utilizaram pequenos dicionários. O cenário SMB utilizou uma senha contra três usuários.

## Reconhecimento

```bash
nmap -sT -sV -p 21,80,139,445 --reason \
  -oN evidence/03-services.txt 192.168.2.98
```

| Porta | Serviço identificado |
|---|---|
| 21/tcp | FTP — vsftpd 2.3.4 |
| 80/tcp | HTTP — Apache 2.2.8 |
| 139/tcp | SMB/NetBIOS — Samba |
| 445/tcp | SMB — Samba |

A identificação de versão não comprova exploração de vulnerabilidades conhecidas.

Evidências: [ambiente](evidence/01-environment.txt), [conectividade](evidence/02-connectivity.txt) e [serviços](evidence/03-services.txt).

## Cenário 1 — FTP

### Preparação e execução

```bash
printf '%s\n' msfadmin user teste > wordlists/ftp-users.txt
printf '%s\n' senha-incorreta lab123 msfadmin > wordlists/ftp-passwords.txt

medusa -h 192.168.2.98 \
  -U wordlists/ftp-users.txt \
  -P wordlists/ftp-passwords.txt \
  -M ftp -t 1 -f
```

Foram previstas até nove combinações. O Medusa encontrou `msfadmin / msfadmin` após três tentativas e interrompeu o teste.

### Validação

Uma conexão manual com o cliente FTP retornou:

```text
230 Login successful.
ftp> pwd
Remote directory: /home/msfadmin
```

Foi comprovada a aceitação da credencial padrão. A evidência publicada é um trecho extraído da gravação original, limitado à validação FTP.

O teste não utilizou opções de FTPS. A quantidade de tentativas não permite concluir se existe bloqueio de contas.

### Evidências

- [Ajuda do módulo](evidence/06-ftp-module-help.txt)
- [Medusa](evidence/07-ftp-medusa.txt)
- [Validação FTP](evidence/08-ftp-validation.txt)

## Cenário 2 — DVWA

### Formulário observado

| Característica | Valor |
|---|---|
| Caminho | /dvwa/vulnerabilities/brute/ |
| Método | GET |
| Parâmetros | username, password, Login |
| Segurança | Low |
| Mensagem de falha | Username and/or password incorrect. |
| Mensagem de sucesso | Welcome to the password protected area admin |

### Controles

Antes da automação, duas requisições com curl confirmaram:

- Senha incorreta: HTTP 200 com mensagem de falha.
- Senha correta: HTTP 200 com mensagem de boas-vindas.

Durante a preparação, uma sessão não aceita retornou HTTP 302 para o login. A sessão foi atualizada antes da execução.

HTTP 200, isoladamente, não distingue sucesso de falha de autenticação.

### Execução

A variável `DVWA_SESSION` representa um cookie de sessão autenticada, obtido localmente. Seu valor não deve ser publicado.

```bash
printf '%s\n' senha-incorreta lab123 password > wordlists/dvwa-passwords.txt

medusa -h 192.168.2.98 \
  -u admin \
  -P wordlists/dvwa-passwords.txt \
  -M web-form \
  -m FORM:/dvwa/vulnerabilities/brute/ \
  -m 'FORM-DATA:get?username=&password=&Login=Login' \
  -m 'DENY-SIGNAL:Username and/or password incorrect.' \
  -m "CUSTOM-HEADER:Cookie: PHPSESSID=${DVWA_SESSION}; security=low" \
  -t 1 -f
```

### Resultado e interpretação

O Medusa identificou `admin / password` na terceira tentativa, consistente com os controles.

O teste avaliou o formulário didático Brute Force dentro de uma sessão já autenticada. Não houve contorno do login inicial do DVWA.

O módulo usa a ausência da mensagem de falha como indicador de possível sucesso. Sessões expiradas, redirecionamentos e erros exigem atenção para evitar falsos positivos.

### Evidências

- [Ajuda do módulo](evidence/09-web-form-module-help.txt)
- [Controles](evidence/10-dvwa-controls.txt)
- [Medusa](evidence/11-dvwa-medusa.txt)

## Cenário 3 — SMB

### Enumeração anônima

```bash
rpcclient -N -U '' 192.168.2.98 -c 'enumdomusers'
```

Foram retornadas **35 contas**, sem fornecimento de credenciais.

A presença de uma conta na enumeração não comprova que ela permita autenticação.

### Password spraying

```bash
printf '%s\n' msfadmin user service > wordlists/smb-users.txt

medusa -h 192.168.2.98 \
  -U wordlists/smb-users.txt \
  -p msfadmin \
  -M smbnt \
  -m GROUP:LOCAL \
  -t 1
```

| Usuário | Resultado observado |
|---|---|
| msfadmin | Sucesso indicado pelo Medusa |
| user | Sem indicação de sucesso |
| service | Sem indicação de sucesso |

### Validação

```bash
smbclient -L //192.168.2.98 -U msfadmin

smbclient //192.168.2.98/msfadmin \
  -U msfadmin -c 'pwd; ls'
```

Foi possível listar os compartilhamentos e as entradas do diretório pessoal.

O Medusa retornou `SUCCESS (ADMIN$ - Access Allowed)`. Entretanto, ADMIN$ foi listado como tipo IPC. Isso não comprova privilégios administrativos no sistema operacional.

Não foram testadas leitura do conteúdo de arquivos, escrita ou execução remota.

### Evidências

- [Ajuda do módulo](evidence/12-smb-module-help.txt)
- [Enumeração](evidence/13-smb-enumeration.txt)
- [Spraying](evidence/14-smb-spraying.txt)
- [Compartilhamentos](evidence/15-smb-validation.txt)
- [Diretório pessoal](evidence/16-smb-home-validation.txt)
- [Contagem de contas](evidence/17-smb-user-count.txt)

## Resumo dos achados

| Achado | Resultado comprovado |
|---|---|
| Credencial padrão no FTP | Login e consulta pwd |
| Senha padrão no DVWA Low | Controles e identificação pelo Medusa |
| Enumeração SMB anônima | Divulgação de 35 contas |
| Mesma credencial em FTP e SMB | msfadmin / msfadmin aceita nos dois serviços |
| Acesso ao compartilhamento pessoal | Listagem de nomes e metadados das entradas |

## Mitigações propostas

| Condição | Medidas |
|---|---|
| Credenciais padrão | Alterar senhas iniciais e desabilitar contas desnecessárias |
| Senhas previsíveis | Utilizar senhas longas e únicas e bloquear senhas comuns |
| Tentativas automatizadas | Aplicar limitação de tentativas e atrasos progressivos |
| Password spraying | Monitorar falhas entre várias contas e utilizar MFA quando suportado |
| FTP sem proteção de transporte | Adotar SFTP ou FTPS conforme a necessidade |
| Enumeração SMB | Restringir consultas anônimas |
| Exposição de serviços | Aplicar firewall e segmentação |
| Protocolos antigos | Atualizar sistemas e avaliar a desativação do SMB1 |
| Compartilhamentos | Revisar permissões e aplicar menor privilégio |
| Detecção | Centralizar logs e criar alertas de autenticação |

As medidas foram propostas; não foram implementadas nem submetidas a reteste.

## Limitações

- Um único alvo e listas pequenas.
- Ausência de avaliação de bloqueio, MFA e limitação de tentativas.
- Ausência de comprovação de privilégios administrativos.
- Ausência de testes de escrita, execução remota ou indisponibilidade.
- DVWA configurado intencionalmente no nível Low.
- Isolamento e modo de rede do VirtualBox não documentados.
- Resultados específicos do laboratório observado.

## Aprendizados

1. Delimitar o alvo e preservar evidências.
2. Diferenciar dicionário de password spraying.
3. Compreender sessões e respostas HTTP antes de automatizar.
4. Validar resultados com um cliente independente.
5. Distinguir autenticação, autorização e privilégio administrativo.
6. Relacionar achados a medidas de prevenção.
7. Registrar limitações e corrigir erros de operação.
8. Revisar gravações para evitar publicação de dados de sessão.

## Organização da entrega

| Local | Conteúdo |
|---|---|
| README.md | Relatório principal |
| evidence/ | Saídas dos comandos e validações |
| wordlists/ | Listas de laboratório |
| images/ | Capturas revisadas, quando adicionadas |
| docs/ | Documentação complementar, quando adicionada |
| scripts/ | Scripts auxiliares, quando adicionados |

## Referências

- [Material do desafio DIO](https://hermes.dio.me/files/assets/2dd3d3ad-b7e5-4325-8d1d-ddd8e7205fea.pdf)
- [Kali Linux](https://www.kali.org/)
- [Medusa](http://www.foofus.net/jmk/medusa/medusa.html)
- [DVWA](https://github.com/digininja/DVWA)
- [Nmap](https://nmap.org/book/)

A sintaxe dos módulos foi conferida pela ajuda da versão instalada do Medusa, preservada nas evidências.
