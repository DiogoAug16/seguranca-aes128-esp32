/*
 * PLACA A - TRANSMISSOR
 * --------------------------------------------------------------------------
 * Trabalho Pratico: AES-128 em dois ESP32 via UART
 *
 * O que faz:
 *   1. Etapa 1: testa o AES com os vetores do FIPS-197 (Apendices B e C.1).
 *   2. Etapa 2: cifra a mensagem em ECB e envia o quadro pela UART2:
 *        [0xAA] [n blocos] [16*n bytes cifrados]   (bytes brutos)
 *   3. Etapa 3: imprime os registros (chave, chaves de rodada 0 e 1,
 *      mensagem com PKCS#7, cifrado, os 5 estados do bloco 1 e o avalanche).
 *
 * Ligacao (UART2, 115200 8N1):
 *   Placa A GPIO17 (TX2) ---> Placa B GPIO16 (RX2)
 *   Placa A GPIO16 (RX2) <--- Placa B GPIO17 (TX2)
 *   GND ------------------- GND
 *
 * Comandos no Monitor Serial (115200, "Nova linha"):
 *   [Enter]      reenvia a mensagem da dupla e mostra a Etapa 3 dela
 *   m <texto>    cifra e envia uma mensagem nova
 *   k <n>        inverte o bit n (0..127) da chave e reenvia
 *   r            restaura a chave original
 *   3            registros da Etapa 3 da ultima mensagem enviada
 *   a            efeito avalanche da ultima mensagem enviada
 *   e            demonstracao do problema do ECB
 */

#include "aes128.h"

/* ===== DADOS DA DUPLA (trocar pelas matriculas reais) =====
 * Tem que ser IGUAL no transmissor e no receptor. */
const char *MATRICULA_A = "2022278440098";
const char *MATRICULA_B = "2022278440080";

/* ===== CONFIGURACAO DA UART ===== */
#define PINO_RX2     16
#define PINO_TX2     17
#define VELOCIDADE   115200
#define MARCADOR     0xAA      /* byte que marca o inicio do quadro   */
#define MAX_BYTES    256       /* tamanho maximo da mensagem cifrada  */
#define COMANDOS     "Comandos: [Enter]=reenvia | m <texto> | k <bit 0..127> | r | 3 | a | e\n"

uint8_t chave[16];             /* chave atual (o comando k inverte um bit dela) */
uint8_t w[NUM_PALAVRAS][4];    /* chaves de rodada (44 palavras)                */
char mensagemDupla[64];        /* "A:<matricula A>;B:<matricula B>"             */
char ultimaMensagem[MAX_BYTES];  /* ultima mensagem enviada (comandos 3 e a)    */


/* =========================================================================
 * IMPRESSAO
 * ========================================================================= */

/* Imprime bytes em hexadecimal, com um espaco a cada bloco de 16 */
void imprimirHex(const uint8_t *dados, int tamanho) {
  for (int i = 0; i < tamanho; i++) {
    Serial.printf("%02X", dados[i]);
    if (i % 16 == 15 && i != tamanho - 1) {
      Serial.print(" ");
    }
  }
  Serial.println();
}

/* Imprime a matriz 4x4 do estado com um titulo */
void imprimirEstado(const char *titulo, uint8_t estado[4][4]) {
  Serial.println(titulo);
  for (int linha = 0; linha < 4; linha++) {
    Serial.printf("      %02X %02X %02X %02X\n",
                  estado[linha][0], estado[linha][1], estado[linha][2], estado[linha][3]);
  }
}

/* Usa a chave atual: gera as 44 palavras das chaves de rodada */
void aplicarChave() {
  expandirChave(chave, w);
  Serial.print("Chave (hex):     ");
  imprimirHex(chave, 16);
}


/* =========================================================================
 * ETAPA 2: CIFRAR E ENVIAR PELA UART
 * ========================================================================= */
void cifrarEEnviar(const char *mensagem) {
  int tamanho = strlen(mensagem);
  if (tamanho >= MAX_BYTES) {
    Serial.println("Mensagem grande demais.");
    return;
  }
  strcpy(ultimaMensagem, mensagem);

  uint8_t comPadding[MAX_BYTES];
  uint8_t cifrado[MAX_BYTES];

  int total = adicionarPadding((const uint8_t *)mensagem, tamanho, comPadding);  /* 1) PKCS#7     */
  int numBlocos = total / 16;
  cifrarECB(comPadding, cifrado, total, w);                                      /* 2) cifra (ECB) */

  /* 3) envia o quadro em bytes brutos (write), nao em texto hexadecimal */
  Serial2.write(MARCADOR);              /* 1 byte: inicio do quadro    */
  Serial2.write(numBlocos);             /* 1 byte: quantos blocos      */
  Serial2.write(cifrado, total);        /* 16*n bytes: blocos cifrados */
  Serial2.flush();                      /* espera terminar de enviar   */

  /* 4) mostra tudo no Monitor Serial */
  Serial.printf("Mensagem:        \"%s\" (%d bytes)\n", mensagem, tamanho);
  Serial.print("Com PKCS#7:      ");
  imprimirHex(comPadding, total);
  Serial.print("Cifrado final:   ");
  imprimirHex(cifrado, total);
  Serial.printf("Quadro enviado (%d bytes): AA %02X + cifrado\n\n", total + 2, numBlocos);
}


/* =========================================================================
 * ETAPA 3: REGISTROS (com a chave atual)
 * ========================================================================= */
void registrosEtapa3(const char *mensagem) {
  Serial.println("=== ETAPA 3: registros ===");
  if (strcmp(mensagem, mensagemDupla) == 0) {
    Serial.printf("Matriculas: A = %s  B = %s\n", MATRICULA_A, MATRICULA_B);
  }
  Serial.printf("Chave (ASCII):   %.16s\n", (const char *)chave);
  Serial.print("Chave (hex):     ");
  imprimirHex(chave, 16);

  /* a chave da rodada r sao as palavras w[4r]..w[4r+3], 16 bytes seguidos */
  Serial.print("Chave rodada 0:  ");
  imprimirHex(w[0], 16);
  Serial.print("Chave rodada 1:  ");
  imprimirHex(w[4], 16);

  uint8_t comPadding[MAX_BYTES];
  uint8_t cifrado[MAX_BYTES];
  int total = adicionarPadding((const uint8_t *)mensagem, strlen(mensagem), comPadding);
  cifrarECB(comPadding, cifrado, total, w);
  Serial.printf("Mensagem:        \"%s\"\n", mensagem);
  Serial.print("Com PKCS#7:      ");
  imprimirHex(comPadding, total);
  Serial.print("Cifrado final:   ");
  imprimirHex(cifrado, total);

  /* Os 5 estados do bloco 1 na rodada 1.
   * Chamamos as transformacoes uma por uma, na mesma ordem do cifrarBloco,
   * para poder imprimir o estado depois de cada uma. */
  uint8_t estado[4][4];
  blocoParaEstado(comPadding, estado);      /* bloco 1 = primeiros 16 bytes */

  Serial.println("\n--- Bloco 1, rodada 1 ---");
  imprimirEstado("(0) Bloco 1 original:", estado);
  addRoundKey(estado, w, 0);
  imprimirEstado("(1) Apos AddRoundKey inicial (chave 0):", estado);
  subBytes(estado);
  imprimirEstado("(2) Apos SubBytes:", estado);
  shiftRows(estado);
  imprimirEstado("(3) Apos ShiftRows:", estado);
  mixColumns(estado);
  imprimirEstado("(4) Apos MixColumns:", estado);
  addRoundKey(estado, w, 1);
  imprimirEstado("(5) Apos AddRoundKey (chave 1):", estado);
  Serial.println();
}


/* =========================================================================
 * EFEITO AVALANCHE: muda 1 bit e conta quantos bits do cifrado mudaram
 * ========================================================================= */
void mostrarDiferenca(const char *titulo, const uint8_t original[16], const uint8_t novo[16]) {
  int bits = contarBitsDiferentes(original, novo, 16);
  Serial.print(titulo);
  imprimirHex(novo, 16);
  Serial.printf("  -> %d de 128 bits mudaram (%.1f%%)\n", bits, bits * 100.0 / 128);
}

void avalanche(const char *mensagem) {
  Serial.println("=== Efeito avalanche (bloco 1) ===");

  uint8_t bloco[MAX_BYTES];
  uint8_t cifradoOriginal[16];
  uint8_t cifradoNovo[16];
  adicionarPadding((const uint8_t *)mensagem, strlen(mensagem), bloco);
  cifrarBloco(bloco, cifradoOriginal, w);
  Serial.print("Cifrado original:          ");
  imprimirHex(cifradoOriginal, 16);

  /* 1) inverte o ultimo bit do 1o byte da CHAVE e cifra de novo */
  uint8_t chave2[16];
  uint8_t w2[NUM_PALAVRAS][4];
  memcpy(chave2, chave, 16);
  chave2[0] ^= 0x01;
  expandirChave(chave2, w2);
  cifrarBloco(bloco, cifradoNovo, w2);
  mostrarDiferenca("1 bit da chave invertido:  ", cifradoOriginal, cifradoNovo);

  /* 2) inverte o ultimo bit do 1o byte da MENSAGEM e cifra de novo */
  bloco[0] ^= 0x01;                          /* ex.: 'A' (0x41) vira '@' (0x40) */
  cifrarBloco(bloco, cifradoNovo, w);
  mostrarDiferenca("1 bit da msg invertido:    ", cifradoOriginal, cifradoNovo);
  Serial.println();
}


/* =========================================================================
 * DEMONSTRACAO DO PROBLEMA DO ECB: bloco 1 == bloco 3
 * ========================================================================= */
void demonstracaoECB() {
  const char *blocos[3] = {"LIGAR LED VERDE.", "DESLIGAR LED    ", "LIGAR LED VERDE."};

  /* 1) os 3 blocos com a chave do exemplo do enunciado (confere com a tabela) */
  uint8_t chaveExemplo[16];
  uint8_t wExemplo[NUM_PALAVRAS][4];
  uint8_t cifrado[16];
  montarChave("20231001", "20231002", chaveExemplo);
  expandirChave(chaveExemplo, wExemplo);

  Serial.println("=== Demonstracao ECB (chave do exemplo do enunciado) ===");
  for (int i = 0; i < 3; i++) {
    cifrarBloco((const uint8_t *)blocos[i], cifrado, wExemplo);
    Serial.printf("Bloco %d \"%s\" -> ", i + 1, blocos[i]);
    imprimirHex(cifrado, 16);
  }
  Serial.println("Repare: o 1o e o 3o bloco cifrado sao IGUAIS.");
  Serial.println("Um espiao na UART ve que o comando se repetiu e pode reenviar o bloco.\n");

  /* 2) envia os mesmos blocos com a chave da dupla. Como 48 bytes ja e
   * multiplo de 16, o PKCS#7 acrescenta um 4o bloco inteiro de 0x10. */
  Serial.println("Enviando os 3 blocos com a chave da dupla (o 4o bloco e o PKCS#7):");
  cifrarEEnviar("LIGAR LED VERDE.DESLIGAR LED    LIGAR LED VERDE.");
}


/* =========================================================================
 * ARDUINO
 * ========================================================================= */
void setup() {
  Serial.begin(VELOCIDADE);                                    /* Monitor Serial */
  Serial2.begin(VELOCIDADE, SERIAL_8N1, PINO_RX2, PINO_TX2);   /* fio ate a placa B */
  delay(1500);

  Serial.println("\n##### PLACA A - TRANSMISSOR AES-128 #####\n");
  Serial.printf("=== ETAPA 1: FIPS-197 (Apendices B e C.1): %s ===\n\n",
                validarFIPS197() ? "OK" : "FALHOU");

  montarChave(MATRICULA_A, MATRICULA_B, chave);
  expandirChave(chave, w);
  snprintf(mensagemDupla, sizeof(mensagemDupla), "A:%s;B:%s", MATRICULA_A, MATRICULA_B);

  Serial.println("=== ETAPA 2: envio pela UART ===");
  cifrarEEnviar(mensagemDupla);

  registrosEtapa3(mensagemDupla);
  avalanche(mensagemDupla);
  Serial.println(COMANDOS);
}

void loop() {
  /* espera alguem digitar algo no Monitor Serial */
  if (Serial.available() == 0) {
    return;
  }

  String comando = Serial.readStringUntil('\n');
  comando.trim();

  if (comando.length() == 0) {
    /* Enter: reenvia a mensagem da dupla e mostra a Etapa 3 dela */
    cifrarEEnviar(mensagemDupla);
    registrosEtapa3(mensagemDupla);
    avalanche(mensagemDupla);

  } else if (comando.startsWith("m ")) {
    /* m <texto>: cifra e envia uma mensagem nova */
    cifrarEEnviar(comando.substring(2).c_str());

  } else if (comando.startsWith("k ")) {
    /* k <n>: inverte o bit n da chave (bit 0 = bit mais alto do byte 0) */
    int bit = comando.substring(2).toInt();
    if (bit < 0 || bit > 127) {
      Serial.println("O bit deve ser de 0 a 127");
      return;
    }
    chave[bit / 8] ^= 0x80 >> (bit % 8);
    Serial.printf("Bit %d da chave invertido.\n", bit);
    aplicarChave();
    Serial.println("(o receptor continua com a chave original -> nao vai conseguir decifrar)");
    cifrarEEnviar(mensagemDupla);

  } else if (comando == "r") {
    /* r: volta para a chave das matriculas */
    montarChave(MATRICULA_A, MATRICULA_B, chave);
    Serial.println("Chave original restaurada.");
    aplicarChave();
    cifrarEEnviar(mensagemDupla);

  } else if (comando == "3") {
    /* 3: registros da Etapa 3 da ultima mensagem enviada (com a chave atual) */
    registrosEtapa3(ultimaMensagem);
    avalanche(ultimaMensagem);

  } else if (comando == "a") {
    avalanche(ultimaMensagem);

  } else if (comando == "e") {
    demonstracaoECB();

  } else {
    Serial.println(COMANDOS);
  }
}
