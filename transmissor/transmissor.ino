/*
 * PLACA A - TRANSMISSOR
 * --------------------------------------------------------------------------
 * Trabalho Pratico: AES-128 em dois ESP32 via UART
 *
 * O que faz:
 *   1. Testa o AES com os vetores do FIPS-197 (Apendices B e C.1).
 *   2. Monta a chave e a mensagem com as matriculas da dupla.
 *   3. Cifra em ECB e envia o quadro pela UART2:
 *        [0xAA] [n blocos] [16*n bytes cifrados]   (bytes brutos)
 *
 * Ligacao (UART2, 115200 8N1):
 *   Placa A GPIO17 (TX2) ---> Placa B GPIO16 (RX2)
 *   Placa A GPIO16 (RX2) <--- Placa B GPIO17 (TX2)
 *   GND ------------------- GND
 *
 * Monitor Serial (115200, "Nova linha"): aperte Enter para reenviar.
 */

#include "aes128.h"

/* ===== DADOS DA DUPLA (trocar pelas matriculas reais) =====
 * Tem que ser IGUAL no transmissor e no receptor. */
const char *MATRICULA_A = "20231001";
const char *MATRICULA_B = "20231002";

/* ===== CONFIGURACAO DA UART ===== */
#define PINO_RX2     16
#define PINO_TX2     17
#define VELOCIDADE   115200
#define MARCADOR     0xAA      /* byte que marca o inicio do quadro   */
#define MAX_BYTES    256       /* tamanho maximo da mensagem cifrada  */

/* ===== VARIAVEIS GLOBAIS ===== */
uint8_t chave[16];                 /* chave atual (pode ter um bit invertido) */
uint8_t chaveOriginal[16];         /* chave montada com as matriculas         */
uint8_t w[NUM_PALAVRAS][4];        /* chaves de rodada (44 palavras)          */
char mensagemDupla[64];            /* "A:<matricula A>;B:<matricula B>"       */


/* =========================================================================
 * FUNCOES DE IMPRESSAO
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

/* Imprime a matriz 4x4 do estado */
void imprimirEstado(uint8_t estado[4][4]) {
  for (int linha = 0; linha < 4; linha++) {
    Serial.print("      ");
    for (int coluna = 0; coluna < 4; coluna++) {
      Serial.printf("%02X ", estado[linha][coluna]);
    }
    Serial.println();
  }
}

/* Imprime a chave da rodada r: sao as palavras w[4r] ate w[4r+3] */
void imprimirChaveRodada(int r) {
  Serial.printf("Chave rodada %d:  ", r);
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      Serial.printf("%02X", w[r * 4 + i][j]);
    }
  }
  Serial.println();
}


/* =========================================================================
 * ETAPA 1: TESTE COM OS VETORES DO FIPS-197
 * ========================================================================= */
void testarVetor(const char *nome, const uint8_t k[16], const uint8_t claro[16], const uint8_t esperado[16]) {
  uint8_t wTeste[NUM_PALAVRAS][4];
  uint8_t cifrado[16];
  uint8_t decifrado[16];

  expandirChave(k, wTeste);
  cifrarBloco(claro, cifrado, wTeste);
  decifrarBloco(cifrado, decifrado, wTeste);

  /* deu certo se o cifrado bate com o esperado e se decifrar volta ao original */
  if (memcmp(cifrado, esperado, 16) == 0 && memcmp(decifrado, claro, 16) == 0) {
    Serial.print("  [OK]     ");
  } else {
    Serial.print("  [FALHOU] ");
  }
  Serial.print(nome);
  Serial.print("  cifrado = ");
  imprimirHex(cifrado, 16);
}

void autoteste() {
  Serial.println("=== ETAPA 1: validacao com FIPS-197 ===");

  /* Apendice B */
  const uint8_t chaveB[16]  = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
  const uint8_t claroB[16]  = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
  const uint8_t cifraB[16]  = {0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32};

  /* Apendice C.1 */
  const uint8_t chaveC[16]  = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
  const uint8_t claroC[16]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
  const uint8_t cifraC[16]  = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};

  testarVetor("Apendice B  ", chaveB, claroB, cifraB);
  testarVetor("Apendice C.1", chaveC, claroC, cifraC);
  Serial.println();
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

  uint8_t comPadding[MAX_BYTES];
  uint8_t cifrado[MAX_BYTES];

  /* 1) completa com PKCS#7 ate dar um multiplo de 16 */
  int total = adicionarPadding((const uint8_t *)mensagem, tamanho, comPadding);
  int numBlocos = total / 16;

  /* 2) cifra todos os blocos em ECB */
  cifrarECB(comPadding, cifrado, total, w);

  /* 3) envia o quadro em bytes brutos (write), nao em texto hexadecimal */
  Serial2.write(MARCADOR);              /* 1 byte: inicio do quadro    */
  Serial2.write(numBlocos);             /* 1 byte: quantos blocos      */
  Serial2.write(cifrado, total);        /* 16*n bytes: blocos cifrados */
  Serial2.flush();                      /* espera terminar de enviar   */

  /* 4) mostra tudo no Monitor Serial */
  Serial.printf("Mensagem: \"%s\" (%d bytes)\n", mensagem, tamanho);
  Serial.print("Com PKCS#7:   ");
  imprimirHex(comPadding, total);
  Serial.print("Cifrado:      ");
  imprimirHex(cifrado, total);
  Serial.printf("Quadro enviado (%d bytes): AA %02X ", total + 2, numBlocos);
  imprimirHex(cifrado, total);
  Serial.println();
}


/* =========================================================================
 * ARDUINO
 * ========================================================================= */
void setup() {
  Serial.begin(VELOCIDADE);                                    /* Monitor Serial */
  Serial2.begin(VELOCIDADE, SERIAL_8N1, PINO_RX2, PINO_TX2);   /* fio ate a placa B */
  delay(1500);

  Serial.println();
  Serial.println("##### PLACA A - TRANSMISSOR AES-128 #####");
  Serial.println();
  autoteste();

  /* monta a chave com as matriculas */
  montarChave(MATRICULA_A, MATRICULA_B, chaveOriginal);
  for (int i = 0; i < 16; i++) {
    chave[i] = chaveOriginal[i];
  }
  expandirChave(chave, w);

  /* monta a mensagem "A:<matricula A>;B:<matricula B>" */
  strcpy(mensagemDupla, "A:");
  strcat(mensagemDupla, MATRICULA_A);
  strcat(mensagemDupla, ";B:");
  strcat(mensagemDupla, MATRICULA_B);

  Serial.println("=== ETAPA 2: envio pela UART ===");
  cifrarEEnviar(mensagemDupla);
}

void loop() {
  /* Enter no Monitor Serial: reenvia a mensagem */
  if (Serial.available() > 0) {
    Serial.readStringUntil('\n');
    cifrarEEnviar(mensagemDupla);
  }
}
