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
const char *MATRICULA_A = "2022278440098";
const char *MATRICULA_B = "2022278440080";

/* ===== CONFIGURACAO DA UART ===== */
#define PINO_RX2     16
#define PINO_TX2     17
#define VELOCIDADE   115200
#define MARCADOR     0xAA
#define MAX_BLOCOS   16
#define TEMPO_LIMITE 500       /* ms esperando os bytes do quadro */

uint8_t chave[16];
uint8_t w[NUM_PALAVRAS][4];    /* chaves de rodada (44 palavras) */


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


/* =========================================================================
 * RECEBE UM QUADRO (chamada depois que o 0xAA chegou)
 * readBytes espera no maximo TEMPO_LIMITE ms e devolve quantos bytes leu.
 * ========================================================================= */
void receberQuadro() {
  /* 1) le o numero de blocos */
  uint8_t numBlocos;
  if (Serial2.readBytes(&numBlocos, 1) != 1) {
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
  int lidos = Serial2.readBytes(cifrado, esperado);
  if (lidos != esperado) {
    Serial.printf("[ERRO] quadro incompleto: chegaram %d de %d bytes\n", lidos, esperado);
    return;
  }

  Serial.printf("=== Quadro recebido: %d bloco(s) ===\n", numBlocos);
  Serial.print("Cifrado:                ");
  imprimirHex(cifrado, esperado);

  /* 3) decifra em ECB */
  uint8_t decifrado[MAX_BLOCOS * 16 + 1];   /* +1 para o '\0' no final */
  decifrarECB(cifrado, decifrado, esperado, w);
  Serial.print("Decifrado (com PKCS#7): ");
  imprimirHex(decifrado, esperado);

  /* 4) remove o PKCS#7 */
  int tamanho = removerPadding(decifrado, esperado);
  if (tamanho < 0) {
    Serial.println("[ERRO] padding PKCS#7 invalido!");
    Serial.println("       -> a chave e diferente da usada para cifrar, ou os dados chegaram corrompidos.\n");
    return;
  }

  /* 5) mostra o texto original */
  decifrado[tamanho] = '\0';      /* termina a string */
  Serial.printf("Texto original: \"%s\"\n\n", (char *)decifrado);
}


/* =========================================================================
 * ARDUINO
 * ========================================================================= */
void setup() {
  Serial.begin(VELOCIDADE);
  Serial2.begin(VELOCIDADE, SERIAL_8N1, PINO_RX2, PINO_TX2);
  Serial2.setTimeout(TEMPO_LIMITE);       /* tempo limite do readBytes */
  delay(1500);

  Serial.println("\n##### PLACA B - RECEPTOR AES-128 #####\n");
  Serial.printf("FIPS-197 (Apendices B e C.1): %s\n", validarFIPS197() ? "OK" : "FALHOU");

  montarChave(MATRICULA_A, MATRICULA_B, chave);
  expandirChave(chave, w);
  Serial.print("Chave (hex): ");
  imprimirHex(chave, 16);
  Serial.println("Aguardando quadros na UART2...\n");
}

void loop() {
  /* Sincronizacao: le byte por byte e descarta tudo ate achar o 0xAA */
  while (Serial2.available() > 0) {
    if (Serial2.read() == MARCADOR) {
      receberQuadro();
    }
  }
}
