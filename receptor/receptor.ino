/*
 * PLACA B - RECEPTOR
 * --------------------------------------------------------------------------
 * Trabalho Pratico: AES-128 em dois ESP32 via UART
 *
 * O que faz:
 *   1. Testa o AES com os vetores do FIPS-197.
 *   2. Monta a mesma chave a partir das matriculas da dupla.
 *   3. Fica esperando o quadro na UART2:
 *        [0xAA] [n blocos] [16*n bytes cifrados]
 *      - sincroniza no 0xAA (ignora qualquer lixo antes dele)
 *      - le n
 *      - le exatamente 16*n bytes, com tempo limite
 *   4. Decifra (ECB), remove o PKCS#7 e mostra o texto no Monitor Serial.
 *
 * Ligacao (UART2, 115200 8N1):
 *   Placa B GPIO16 (RX2) <--- Placa A GPIO17 (TX2)
 *   Placa B GPIO17 (TX2) ---> Placa A GPIO16 (RX2)
 *   GND ------------------- GND
 */

#include "aes128.h"

/* ===== DADOS DA DUPLA (iguais aos do transmissor) ===== */
const char *MATRICULA_A = "20231001";
const char *MATRICULA_B = "20231002";

/* ===== CONFIGURACAO DA UART ===== */
#define PINO_RX2     16
#define PINO_TX2     17
#define VELOCIDADE   115200
#define MARCADOR     0xAA
#define MAX_BLOCOS   16
#define TEMPO_LIMITE 500       /* ms esperando os bytes do quadro */

/* ===== VARIAVEIS GLOBAIS ===== */
uint8_t chave[16];
uint8_t w[NUM_PALAVRAS][4];    /* chaves de rodada (44 palavras) */


/* =========================================================================
 * IMPRESSAO
 * ========================================================================= */
void imprimirHex(const uint8_t *dados, int tamanho) {
  for (int i = 0; i < tamanho; i++) {
    Serial.printf("%02X", dados[i]);
    if (i % 16 == 15 && i != tamanho - 1) {
      Serial.print(" ");
    }
  }
  Serial.println();
}


/* =========================================================================
 * TESTE COM OS VETORES DO FIPS-197
 * ========================================================================= */
void testarVetor(const char *nome, const uint8_t k[16], const uint8_t claro[16], const uint8_t esperado[16]) {
  uint8_t wTeste[NUM_PALAVRAS][4];
  uint8_t cifrado[16];
  uint8_t decifrado[16];

  expandirChave(k, wTeste);
  cifrarBloco(claro, cifrado, wTeste);
  decifrarBloco(cifrado, decifrado, wTeste);

  if (memcmp(cifrado, esperado, 16) == 0 && memcmp(decifrado, claro, 16) == 0) {
    Serial.print("  [OK]     ");
  } else {
    Serial.print("  [FALHOU] ");
  }
  Serial.println(nome);
}

void autoteste() {
  Serial.println("=== Validacao com FIPS-197 ===");

  const uint8_t chaveB[16]  = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
  const uint8_t claroB[16]  = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
  const uint8_t cifraB[16]  = {0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32};

  const uint8_t chaveC[16]  = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
  const uint8_t claroC[16]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
  const uint8_t cifraC[16]  = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};

  testarVetor("Apendice B  ", chaveB, claroB, cifraB);
  testarVetor("Apendice C.1", chaveC, claroC, cifraC);
  Serial.println();
}


/* =========================================================================
 * RECEBE UM QUADRO (chamada depois que o 0xAA chegou)
 * ========================================================================= */
void receberQuadro() {

  /* 1) le o numero de blocos (espera no maximo TEMPO_LIMITE ms) */
  uint8_t numBlocos;
  int lidos = Serial2.readBytes(&numBlocos, 1);
  if (lidos != 1) {
    Serial.println("[ERRO] tempo esgotado esperando o numero de blocos");
    return;
  }
  if (numBlocos == 0 || numBlocos > MAX_BLOCOS) {
    Serial.printf("[ERRO] numero de blocos invalido: %d\n", numBlocos);
    return;                       /* volta a procurar o proximo 0xAA */
  }

  /* 2) le exatamente 16*n bytes */
  uint8_t cifrado[MAX_BLOCOS * 16];
  int esperado = numBlocos * 16;
  lidos = Serial2.readBytes(cifrado, esperado);
  if (lidos != esperado) {
    Serial.printf("[ERRO] quadro incompleto: chegaram %d de %d bytes\n", lidos, esperado);
    return;
  }

  Serial.println("=== Quadro recebido ===");
  Serial.printf("Blocos (n): %d\n", numBlocos);
  for (int b = 0; b < numBlocos; b++) {
    Serial.printf("  Cifrado bloco %d: ", b + 1);
    imprimirHex(&cifrado[b * 16], 16);
  }

  /* 3) decifra em ECB */
  uint8_t decifrado[MAX_BLOCOS * 16 + 1];   /* +1 para o '\0' no final */
  decifrarECB(cifrado, decifrado, esperado, w);
  Serial.print("Decifrado (com PKCS#7): ");
  imprimirHex(decifrado, esperado);

  /* 4) remove o PKCS#7 */
  int tamanho = removerPadding(decifrado, esperado);
  if (tamanho < 0) {
    Serial.println("[ERRO] padding PKCS#7 invalido!");
    Serial.println("       -> a chave e diferente da usada para cifrar, ou os dados chegaram corrompidos.");
    Serial.println();
    return;
  }

  /* 5) mostra o texto original */
  decifrado[tamanho] = '\0';      /* termina a string */
  Serial.printf("Texto original: \"%s\"\n", (char *)decifrado);
  Serial.println();
}


/* =========================================================================
 * ARDUINO
 * ========================================================================= */
void setup() {
  Serial.begin(VELOCIDADE);
  Serial2.begin(VELOCIDADE, SERIAL_8N1, PINO_RX2, PINO_TX2);
  Serial2.setTimeout(TEMPO_LIMITE);       /* tempo limite do readBytes */
  delay(1500);

  Serial.println();
  Serial.println("##### PLACA B - RECEPTOR AES-128 #####");
  Serial.println();
  autoteste();

  montarChave(MATRICULA_A, MATRICULA_B, chave);
  expandirChave(chave, w);
  Serial.print("Chave (hex): ");
  imprimirHex(chave, 16);
  Serial.println("Aguardando quadros na UART2...");
  Serial.println();
}

void loop() {
  /* Sincronizacao: le byte por byte e descarta tudo ate achar o 0xAA */
  while (Serial2.available() > 0) {
    uint8_t byteLido = Serial2.read();
    if (byteLido == MARCADOR) {
      receberQuadro();
    }
  }
}
