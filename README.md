# AES-128 em dois ESP32 via UART

Trabalho prático de Segurança de Sistemas de Computação (IFMT).
AES-128 implementado do zero (sem biblioteca de criptografia), modo ECB com PKCS#7.
A placa A cifra a mensagem da dupla e envia pela UART2; a placa B decifra e mostra o texto.

## Fluxo

### Transmissor e receptor

```mermaid
%%{init: {"flowchart": {"curve": "linear"}}}%%
flowchart LR
    subgraph A["Placa A: transmissor.ino"]
        direction TB
        A1["setup: Etapa 1<br/>valida o AES com o FIPS-197"] --> A2["montarChave + expandirChave<br/>chave das matrículas e 11 chaves de rodada"]
        A2 --> A3["mensagem A:...;B:...<br/>(ou uma nova, pelo comando m)"]
        A3 --> A4["adicionarPadding<br/>PKCS#35;7 até múltiplo de 16 bytes"]
        A4 --> A5["cifrarECB<br/>AES-128 em cada bloco"]
        A5 --> A6["Serial2.write<br/>quadro: AA + n + 16 × n bytes"]
    end

    subgraph B["Placa B: receptor.ino"]
        direction TB
        B0["setup: valida o FIPS-197<br/>e monta a mesma chave"] --> B1
        B1["loop: descarta bytes até chegar o 0xAA"] --> B2{"chegou n<br/>entre 1 e 16?"}
        B2 -- não --> B1
        B2 -- sim --> B3{"chegaram os 16 × n bytes<br/>em até 500 ms?"}
        B3 -- não --> B1
        B3 -- sim --> B4["decifrarECB<br/>AES-128 inverso em cada bloco"]
        B4 --> B5{"padding PKCS#35;7<br/>válido?"}
        B5 -- não --> B6["avisa: chave diferente<br/>ou dados corrompidos"] --> B1
        B5 -- sim --> B7["removerPadding e mostra<br/>o texto original"]
    end

    A -- "quadro pela UART2<br/>115200 bps, 8N1" --> B
```

### AES-128: cifrar um bloco (`cifrarBloco`)

```mermaid
%%{init: {"flowchart": {"curve": "linear"}}}%%
flowchart TD
    C1["Chave de 16 bytes"] --> C2["expandirChave<br/>11 chaves de rodada: 0 a 10"]
    M1["Bloco de 16 bytes"] --> M2["blocoParaEstado<br/>matriz 4×4, coluna por coluna"]
    M2 --> R0["AddRoundKey<br/>XOR com a chave 0"]
    C2 --> R0
    R0 --> R1["rodada = 1"]
    R1 --> S1["SubBytes<br/>troca cada byte pela S-box"]
    S1 --> S2["ShiftRows<br/>gira as linhas 0, 1, 2 e 3 casas"]
    S2 --> D1{"rodada = 10?"}
    D1 -- não --> S3["MixColumns<br/>mistura cada coluna com gmul"]
    S3 --> S4["AddRoundKey<br/>XOR com a chave da rodada"]
    D1 -- sim --> S4
    C2 --> S4
    S4 --> D2{"rodada = 10?"}
    D2 -- não --> R2["rodada + 1"]
    R2 --> S1
    D2 -- sim --> F1["estadoParaBloco<br/>bloco cifrado de 16 bytes"]
```

A decifragem (`decifrarBloco`) faz o caminho inverso: começa pela chave 10 e vai até a 0,
usando InvShiftRows, InvSubBytes, AddRoundKey e InvMixColumns (que não entra no último passo).

## Estrutura

```
transmissor/
  transmissor.ino   placa A: autoteste, registros da Etapa 3, cifra e envia
  aes128.h          AES-128 (igual nas duas pastas)
receptor/
  receptor.ino      placa B: sincroniza no 0xAA, lê, decifra, remove PKCS#7
  aes128.h
teste_pc/
  teste.c           testes no PC (FIPS-197 + valores do enunciado)
```

## Antes de gravar

Troque as matrículas no topo **dos dois** `.ino` (têm que ser iguais):

```c
const char *MATRICULA_A = "20231001";
const char *MATRICULA_B = "20231002";
```

## Ligação (UART2, 115200 bps, 8N1)

| Placa A        | Placa B        |
|----------------|----------------|
| GPIO17 (TX2)   | GPIO16 (RX2)   |
| GPIO16 (RX2)   | GPIO17 (TX2)   |
| GND            | GND            |

## Quadro enviado

| Campo            | Tamanho     |
|------------------|-------------|
| Marcador `0xAA`  | 1 byte      |
| Nº de blocos `n` | 1 byte      |
| Blocos cifrados  | 16 × n bytes |

Enviado em bytes brutos (`Serial2.write`), não em texto hexadecimal.

## Comandos no Monitor Serial da placa A (115200, "Nova linha")

| Comando       | O que faz |
|---------------|-----------|
| Enter         | reenvia a mensagem da dupla e mostra a Etapa 3 dela |
| `m <texto>`   | cifra e envia uma mensagem nova |
| `k <n>`       | inverte o bit `n` (0..127) da chave e reenvia (o receptor acusa padding inválido) |
| `r`           | restaura a chave original |
| `a`           | efeito avalanche da última mensagem enviada |
| `e`           | demonstração do problema do ECB (bloco 1 = bloco 3) |

## Onde está cada parte do AES (`aes128.h`)

| Etapa | Função |
|-------|--------|
| Bloco ↔ matriz 4×4 | `blocoParaEstado` / `estadoParaBloco` |
| Expansão de chave | `expandirChave` (RotWord, SubWord e Rcon dentro dela) |
| AddRoundKey | `addRoundKey` |
| SubBytes / inversa | `subBytes` / `invSubBytes` (via `substituirBytes`) |
| ShiftRows / inversa | `shiftRows` / `invShiftRows` (via `girarLinhas`) |
| MixColumns / inversa | `mixColumns` / `invMixColumns` (via `multiplicarColunas`, matrizes `MIX` / `INV_MIX`) |
| Multiplicação em GF(2⁸) | `xtime`, `gmul` |
| Cifrar / decifrar 1 bloco | `cifrarBloco` / `decifrarBloco` |
| PKCS#7 | `adicionarPadding` / `removerPadding` |
| ECB | `cifrarECB` / `decifrarECB` |
| Chave das matrículas | `montarChave` |
| Validação FIPS-197 (nas duas placas) | `testarFIPS197` / `validarFIPS197` |

A S-box e a S-box inversa foram tiradas do FIPS-197 (NIST), Tabelas 4 e 6:
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf

## Teste no PC

```
cd teste_pc
gcc -I../transmissor teste.c -o teste && ./teste
```

Confere os vetores do FIPS-197 (Apêndices B e C.1), os 5 estados da rodada 1,
o exemplo do enunciado e os 3 blocos da demonstração do ECB. Também confere a origem das
tabelas fixas: a S-box (inverso em GF(2⁸) + transformação afim), o Rcon (`xtime` a partir de `01`)
e as matrizes do MixColumns (`MIX` × `INV_MIX` = identidade).
