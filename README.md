# Detectar tentativas de exfiltração HTTP e ICMP

> **Plataforma:** TryHackMe / LetsDefend  
> **Ferramentas:** Wireshark · Splunk (SPL)  
> **Protocolos analisados:** HTTP · ICMP  
> **Objetivo:** Detectar e investigar tentativas de exfiltração de dados usando análise de tráfego de rede (PCAP) e correlação de logs em SIEM.
---

## HTTP Exfiltration

### Conceito

HTTP/HTTPS é o protocolo mais universal da internet — atravessa firewalls sem restrição na grande maioria dos ambientes. Atacantes aproveitam isso para **embutir dados em requisições POST** direcionadas a servidores externos ou serviços legítimos de nuvem (Dropbox, GitHub, S3).

A detecção é mais difícil porque o tráfego se mistura ao uso legítimo da web.

### Como atacantes usam HTTP

| Técnica | Descrição |
|---|---|
| **POST para C2** | Grandes volumes de dados no body de requisições POST para hosts controlados pelo atacante |
| **GET com dados codificados** | Pequenos fragmentos inseridos em query strings ou segmentos de URL |
| **Serviços CDN/legítimos** | Exfiltração disfarçada como upload para Dropbox, GitHub, S3, Azure Blob |
| **Cabeçalhos customizados** | Dados em headers como `X-Data: <base64>` — evade DLP baseado em strings |
| **Transferência fragmentada** | Dados divididos em múltiplas requisições pequenas para evitar limites de tamanho |
| **HTTPS/TLS tunneling** | Canal criptografado oculta o payload — requer inspeção TLS ou análise de metadados |

### Indicadores de Ataque (IoAs)

- Requisições POST excepcionalmente grandes para hosts externos/inesperados
- Domínios com baixa reputação ou raramente vistos no tráfego normal
- Pequenas requisições frequentes (beaconing) seguidas de grandes uploads
- Transferências fragmentadas/multipart compondo um arquivo maior
- URI com padrão `/sync/upload`, `/api/upload`, `/v1/data` para domínios desconhecidos

---

### Splunk — Correlação de Logs HTTP

**Passo 1 — Visão geral dos logs HTTP**
```spl
index="data_exfil" sourcetype="http_logs"
```
<img width="1909" height="654" alt="image" src="https://github.com/user-attachments/assets/1bfbdae1-2ca3-4e1f-83ab-4e0ccee42e9f" />


> Carrega todos os eventos HTTP. Analise os campos disponíveis: `src_ip`, `dst_ip`, `domain`, `method`, `bytes_sent`, `uri`.

---

**Passo 2 — Filtrar apenas requisições POST**
```spl
index="data_exfil" sourcetype="http_logs" method=POST
```
<img width="1903" height="721" alt="image" src="https://github.com/user-attachments/assets/dc91d286-5ad5-4e3b-be3f-244833ba80c4" />


> Requisições GET raramente contêm grandes volumes de dados. POST é o método padrão para envio — filtrar por ele já reduz significativamente o ruído.

---

**Passo 3 — Analisar volume médio por domínio**
```spl
index="data_exfil" sourcetype="http_logs" method=POST
| stats count avg(bytes_sent) max(bytes_sent) min(bytes_sent) by domain
| sort -count
```
<img width="1916" height="708" alt="image" src="https://github.com/user-attachments/assets/22cd5250-bb27-445d-a2ec-f315a16578ff" />


> Compara o volume médio de bytes enviados para cada domínio. Domínios legítimos (google.com, microsoft.com) terão padrões consistentes. Um domínio desconhecido com `avg(bytes_sent)` alto é suspeito imediato.

---

**Passo 4 — Isolar requisições com volume anormal**
```spl
index="data_exfil" sourcetype="http_logs" method=POST bytes_sent > 600
| table _time src_ip uri domain dst_ip bytes_sent
| sort -bytes_sent
```
<img width="1913" height="472" alt="image" src="https://github.com/user-attachments/assets/2a5cbc26-e2a7-4f94-b957-6c918ccf0550" />

> O threshold de 600 bytes elimina o ruído de requisições pequenas (status checks, beaconing) e isola as transferências reais de dados. Ajuste o valor conforme o baseline do ambiente.

---

### Wireshark — Análise do `http_lab.pcap`

**Passo 1 — Isolar tráfego HTTP**
```
http
```
> Exibe todas as requisições e respostas HTTP. Observe os métodos (GET/POST), URIs e IPs de destino.
---

**Passo 2 — Filtrar apenas POSTs**
```
http.request.method == "POST"
```
<img width="1912" height="868" alt="image" src="https://github.com/user-attachments/assets/cedd7452-1534-46e3-9b82-28c989a361b9" />

---

**Passo 3 — Adicionar filtro de tamanho (primeira passagem)**
```
http.request.method == "POST" and frame.len > 500
```
<img width="1742" height="872" alt="image" src="https://github.com/user-attachments/assets/06573840-c2fc-4c01-931d-fb6bdbbd0270" />


> Reduz o volume de resultados mantendo apenas frames com conteúdo real. Em ambientes ruidosos, ainda pode retornar muitos resultados legítimos.

---

**Passo 4 — Refinar o threshold (segunda passagem)**
```
http.request.method == "POST" and frame.len > 750
```
<img width="1910" height="263" alt="image" src="https://github.com/user-attachments/assets/ea6b16f7-60ef-4a52-9f88-1fc4377c30ad" />

> Técnica de **refinamento iterativo**: aumentar progressivamente o threshold até restar apenas o tráfego verdadeiramente anômalo. No lab, este filtro isolou exatamente **uma entrada** — a exfiltração confirmada.
> Após isolar o pacote: **Follow → TCP Stream** para visualizar o conteúdo completo enviado.
<img width="1595" height="523" alt="image" src="https://github.com/user-attachments/assets/107ab3d6-b502-408f-bc5e-3b02ca4f0d26" />

---

### Findings

| Indicador | Valor |
|---|---|
| Host comprometido | `192.168.1.103` |
| Destino | `api.cloudsync-services.com` |
| URI | `/v1/sync/upload` |
| Conteúdo exfiltrado | Credenciais de acesso interno — Finance Dept + hashes de arquivos |
| Flag | `THM{http_raw_3xf1ltr4t10n_succ3ss}` |
<img width="756" height="417" alt="image" src="https://github.com/user-attachments/assets/a0cc5fc0-9d4a-4dc7-ae15-09446a2c07c5" />

---

##  ICMP Exfiltration

### Conceito

O ICMP (Internet Control Message Protocol) é usado para diagnóstico de rede — o famoso `ping`. Por ser considerado inofensivo, **raramente é inspecionado em profundidade** por firewalls e IDS.

Atacantes inserem dados codificados (Base64, hex) dentro do **payload** dos pacotes ICMP Echo Request (tipo 8). Um servidor remoto controlado pelo atacante recebe, remonta e decodifica os fragmentos.

Um ping normal tem aproximadamente **74 bytes no total**. Qualquer pacote ICMP acima de 100 bytes já é considerado suspeito.

### Como atacantes usam ICMP

| Técnica | Descrição |
|---|---|
| **Echo tunneling (tipo 8/0)** | Dados codificados inseridos no payload de ping request/reply |
| **Tipos/códigos customizados** | Uso de tipos ICMP incomuns (ex: timestamp 13/14) para evadir assinaturas |
| **Fragmentação** | Grandes payloads divididos em múltiplos pacotes para evitar detecção por tamanho |
| **Criptografia/ofuscação** | Base64 ou XOR para que o payload pareça dados aleatórios |

### Indicadores de Ataque (IoAs)

- Um único host enviando múltiplos Echo Requests para IP externo
- `frame.len` > 100 bytes (pings normais têm ~74 bytes)
- Payloads com alta entropia ou padrões Base64/hexadecimal
- Temporização regular — pacotes espaçados uniformemente (comportamento de sinalização)
- Ausência de resposta Echo (atacante não precisa da resposta)
- Rajadas ICMP sem tráfego legítimo de aplicações do mesmo host

---

### Wireshark — Análise do `icmp_lab.pcap`

**Passo 1 — Isolar todo tráfego ICMP**
```
icmp
```
<img width="1906" height="888" alt="image" src="https://github.com/user-attachments/assets/2b5e470a-8068-4937-9d42-3f5cd2cdc744" />

> Exibe todos os pacotes ICMP da captura. Observe o volume total e os IPs de destino. Pings legítimos normalmente vão para IPs internos ou gateways conhecidos.

---

**Passo 2 — Focar nos Echo Requests**
```
icmp.type == 8
```
> `type == 8` são os **Echo Requests** — pacotes saindo do host comprometido em direção ao C2. Os `type == 0` são as respostas (replies). Filtrar apenas os requests isola o fluxo de saída de dados.

---

**Passo 3 — Detectar payloads anômalos**
```
icmp.type == 8 and frame.len > 100
```
<img width="1913" height="290" alt="image" src="https://github.com/user-attachments/assets/f1e9608a-1379-42f3-a404-5a563c328933" />

> Este é o filtro definitivo. Pings normais têm ~74 bytes. Qualquer Echo Request acima de 100 bytes contém um payload suspeito. Clique no pacote e expanda **Internet Control Message Protocol → Data** para inspecionar o conteúdo codificado.

---

### Findings

| Indicador | Valor |
|---|---|
| Host comprometido | `192.168.1.101` |
| Destino | `10.0.0.254` (externo) |
| Tamanho dos pacotes suspeitos | 148 bytes (normal: 74 bytes) |
| Total de pacotes anômalos | 5 |
| Conteúdo identificado no payload | Credenciais + hashes de arquivos (`secret.txt`, `backup.tar`) |
| Flag | `THM{icmp_3ch0_3xf1ltr4t10n_succ3ss}` |
<img width="893" height="546" alt="image" src="https://github.com/user-attachments/assets/d9a2c246-9fad-4857-bb21-15baf34f3e42" />

---

## 📊 Resumo — IoAs por Protocolo

| Protocolo | Principal IoA | Ferramenta | Filtro/Query chave |
|---|---|---|---|
| **HTTP** | POST com bytes_sent alto para domínio desconhecido | Splunk / Wireshark | `method=POST bytes_sent > 600` |
| **ICMP** | Echo Request com frame.len > 100 bytes | Wireshark | `icmp.type == 8 and frame.len > 100` |

---

## Referências MITRE ATT&CK

| Técnica | ID | Descrição |
|---|---|---||
| Exfiltration Over Web Service | [T1567](https://attack.mitre.org/techniques/T1567/) | HTTP/HTTPS para serviços de nuvem |
| Protocol Tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) | DNS/ICMP tunneling |

---

## Stack Utilizada

| Ferramenta | Uso |
|---|---|
| **Wireshark** | Análise de arquivos PCAP |
| **Splunk (SPL)** | Correlação de logs |
| **TryHackMe** | Ambiente de laboratório controlado |

---

*Documentado por Nicolas Farias — SOC Analyst | Cybersecurity Research & SOC Labs*
