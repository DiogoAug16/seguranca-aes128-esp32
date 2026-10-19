/*
 * aes128.h
 * --------------------------------------------------------------------------
 * Trabalho Pratico: AES-128 em dois ESP32 via UART
 * Seguranca de Sistemas de Computacao - IFMT
 *
 * Este arquivo e o MESMO no transmissor e no receptor.
 * Ele so tem o AES em si (cifrar/decifrar 1 bloco de 16 bytes), o PKCS#7 e
 * o ECB. Nada de Serial aqui, para poder testar tambem no PC.
 *
 * Organizacao do estado:
 *   O AES enxerga o bloco de 16 bytes como uma tabela 4x4, que chamamos de
 *   ESTADO. A tabela e preenchida POR COLUNA: os 4 primeiros bytes da
 *   mensagem viram a coluna 0, os 4 seguintes a coluna 1, e assim por diante.
 *
 *   Posicao de cada byte do bloco dentro da matriz estado[linha][coluna]:
 *
 *        coluna: 0    1    2    3
 *   linha 0:  [ 0] [ 4] [ 8] [12]
 *   linha 1:  [ 1] [ 5] [ 9] [13]
 *   linha 2:  [ 2] [ 6] [10] [14]
 *   linha 3:  [ 3] [ 7] [11] [15]
 */
#ifndef AES128_H
#define AES128_H

#include <stdint.h>
#include <string.h>

#define NUM_PALAVRAS   44   /* 11 chaves de rodada x 4 palavras = 44 palavras */

/* ==========================================================================
 * S-BOX (FIPS-197, Tabela 4)
 * --------------------------------------------------------------------------
 * Para cada byte x:
 *   1) calcula o inverso de x no corpo GF(2^8) (o 0 vira 0);
 *   2) aplica uma transformacao afim fixa nos bits e faz XOR com 0x63.
 * O resultado e uma tabela de 256 valores sem relacao linear com a entrada.
 * Usamos a tabela pronta porque e muito mais rapido do que calcular isso a
 * cada byte.
 *
 * Como consultar: o byte 0x19 -> linha 1, coluna 9 da tabela -> 0xd4.
 * ========================================================================== */
const uint8_t SBOX[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* S-box inversa (FIPS-197, Tabela 6): desfaz a S-box (INV_SBOX[SBOX[x]] == x).
 * Usada para decifrar. */
const uint8_t INV_SBOX[256] = {
  0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
  0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
  0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
  0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
  0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
  0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
  0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
  0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
  0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
  0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
  0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
  0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
  0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
  0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
  0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
  0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

/* Rcon: constante de cada rodada da expansao de chave (so o 1o byte importa;
 * os outros 3 bytes da palavra sao 00). Cada valor e o anterior x2 em GF(2^8). */
const uint8_t RCON[10] = {
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* Matrizes fixas do MixColumns e do InvMixColumns */
const uint8_t MIX[4][4] = {
  {0x02, 0x03, 0x01, 0x01},
  {0x01, 0x02, 0x03, 0x01},
  {0x01, 0x01, 0x02, 0x03},
  {0x03, 0x01, 0x01, 0x02}
};
const uint8_t INV_MIX[4][4] = {
  {0x0e, 0x0b, 0x0d, 0x09},
  {0x09, 0x0e, 0x0b, 0x0d},
  {0x0d, 0x09, 0x0e, 0x0b},
  {0x0b, 0x0d, 0x09, 0x0e}
};


/* ==========================================================================
 * PASSAR O BLOCO PARA A MATRIZ E DE VOLTA (preenchendo POR COLUNA)
 * ========================================================================== */
void blocoParaEstado(const uint8_t bloco[16], uint8_t estado[4][4]) {
  for (int coluna = 0; coluna < 4; coluna++)
    for (int linha = 0; linha < 4; linha++)
      estado[linha][coluna] = bloco[coluna * 4 + linha];
}

void estadoParaBloco(uint8_t estado[4][4], uint8_t bloco[16]) {
  for (int coluna = 0; coluna < 4; coluna++)
    for (int linha = 0; linha < 4; linha++)
      bloco[coluna * 4 + linha] = estado[linha][coluna];
}


/* ==========================================================================
 * MULTIPLICACAO EM GF(2^8)
 * --------------------------------------------------------------------------
 * No AES a "soma" de bytes e o XOR, e a multiplicacao tem regras proprias.
 * Tudo e montado a partir da multiplicacao por 2 (xtime).
 * ========================================================================== */

/* xtime: multiplica um byte por 2 em GF(2^8).
 * Desloca 1 bit para a esquerda; se o bit mais alto era 1 (o byte "estourou"
 * os 8 bits), faz XOR com 0x1B, que e o polinomio redutor x^8+x^4+x^3+x+1
 * sem o x^8. Isso mantem o resultado dentro de 1 byte.
 * Ex.: xtime(0xd4) -> 0xa8 ^ 0x1b = 0xb3 */
uint8_t xtime(uint8_t x) {
  if (x & 0x80) {
    return (x << 1) ^ 0x1b;
  }
  return x << 1;
}

/* gmul: multiplica x por n em GF(2^8), so com xtime e XOR.
 * Para cada bit 1 de n soma (XOR) a potencia de 2 correspondente de x.
 * Ex.: x * 0x0b = x*8 ^ x*2 ^ x  (0x0b = 1011 em binario) */
uint8_t gmul(uint8_t x, uint8_t n) {
  uint8_t resultado = 0;
  while (n) {
    if (n & 1) {
      resultado ^= x;
    }
    x = xtime(x);   /* x, 2x, 4x, 8x, ... */
    n >>= 1;
  }
  return resultado;
}


/* ==========================================================================
 * EXPANSAO DE CHAVE (Key Expansion)
 * --------------------------------------------------------------------------
 * Transforma a chave de 16 bytes em 11 chaves de rodada.
 * Trabalha com "palavras" de 4 bytes: w[0] ate w[43].
 *   - w[0..3]   = a propria chave
 *   - w[i]      = w[i-1] XOR w[i-4]
 *   - quando i e multiplo de 4, antes do XOR, w[i-1] passa por:
 *       RotWord (gira 1 byte), SubWord (S-box em cada byte) e XOR com Rcon.
 * A chave da rodada r sao as palavras w[4r], w[4r+1], w[4r+2], w[4r+3]
 * (16 bytes seguidos na memoria).
 * ========================================================================== */
void expandirChave(const uint8_t chave[16], uint8_t w[NUM_PALAVRAS][4]) {
  memcpy(w, chave, 16);   /* w[0..3] = a propria chave */

  for (int i = 4; i < NUM_PALAVRAS; i++) {
    for (int j = 0; j < 4; j++) {
      uint8_t temp = w[i - 1][j];          /* temp = w[i-1] */

      /* A cada 4 palavras (inicio de uma nova chave de rodada): o "tempero" */
      if (i % 4 == 0) {
        /* RotWord ([a b c d] -> [b c d a]: pega o byte j+1) + SubWord (S-box) */
        temp = SBOX[w[i - 1][(j + 1) % 4]];
        if (j == 0) {
          temp ^= RCON[i / 4 - 1];         /* XOR com Rcon (deixa cada rodada diferente) */
        }
      }

      w[i][j] = w[i - 4][j] ^ temp;        /* w[i] = w[i-4] XOR temp */
    }
  }
}


/* ==========================================================================
 * AS 4 TRANSFORMACOES E SUAS INVERSAS
 * ========================================================================== */

/* AddRoundKey: XOR de cada byte do estado com a chave da rodada.
 * E a UNICA etapa que usa a chave. XOR e sua propria inversa, entao
 * a mesma funcao serve para cifrar e decifrar.
 * A coluna c do estado faz XOR com a palavra w[4*rodada + c]. */
void addRoundKey(uint8_t estado[4][4], uint8_t w[NUM_PALAVRAS][4], int rodada) {
  for (int coluna = 0; coluna < 4; coluna++)
    for (int linha = 0; linha < 4; linha++)
      estado[linha][coluna] ^= w[rodada * 4 + coluna][linha];
}

/* SubBytes: troca cada byte pelo valor da tabela (confusao, nao linear).
 * Cifrar usa a SBOX; decifrar usa a INV_SBOX. */
void substituirBytes(uint8_t estado[4][4], const uint8_t tabela[256]) {
  for (int linha = 0; linha < 4; linha++)
    for (int coluna = 0; coluna < 4; coluna++)
      estado[linha][coluna] = tabela[estado[linha][coluna]];
}
void subBytes(uint8_t estado[4][4])    { substituirBytes(estado, SBOX); }
void invSubBytes(uint8_t estado[4][4]) { substituirBytes(estado, INV_SBOX); }

/* ShiftRows: a linha L gira L casas para a ESQUERDA (linha 0 fica parada).
 * Na posicao c entra o byte que estava na coluna (c + L).
 *   linha 1: [a b c d] -> [b c d a]
 * InvShiftRows faz o contrario: gira L casas para a DIREITA (coluna c - L). */
void girarLinhas(uint8_t estado[4][4], int sentido) {   /* +1 esquerda, -1 direita */
  for (int linha = 1; linha < 4; linha++) {
    uint8_t copia[4];
    memcpy(copia, estado[linha], 4);
    for (int coluna = 0; coluna < 4; coluna++) {
      estado[linha][coluna] = copia[(coluna + sentido * linha + 4) % 4];
    }
  }
}
void shiftRows(uint8_t estado[4][4])    { girarLinhas(estado, +1); }
void invShiftRows(uint8_t estado[4][4]) { girarLinhas(estado, -1); }

/* MixColumns: mistura os 4 bytes de cada coluna (difusao).
 * Cada coluna e multiplicada pela matriz fixa MIX em GF(2^8)
 * ("soma" = XOR, "vezes" = gmul). InvMixColumns usa a matriz INV_MIX.
 * Ex.: novo byte 0 = 02*a0 ^ 03*a1 ^ 01*a2 ^ 01*a3 */
void multiplicarColunas(uint8_t estado[4][4], const uint8_t matriz[4][4]) {
  for (int coluna = 0; coluna < 4; coluna++) {
    uint8_t a[4];   /* copia da coluna: cada byte novo usa os 4 antigos */
    for (int linha = 0; linha < 4; linha++) {
      a[linha] = estado[linha][coluna];
    }
    for (int linha = 0; linha < 4; linha++) {
      estado[linha][coluna] = gmul(a[0], matriz[linha][0]) ^ gmul(a[1], matriz[linha][1])
                            ^ gmul(a[2], matriz[linha][2]) ^ gmul(a[3], matriz[linha][3]);
    }
  }
}
void mixColumns(uint8_t estado[4][4])    { multiplicarColunas(estado, MIX); }
void invMixColumns(uint8_t estado[4][4]) { multiplicarColunas(estado, INV_MIX); }


/* ==========================================================================
 * CIFRAR E DECIFRAR 1 BLOCO
 * ========================================================================== */

/* Cifra 1 bloco de 16 bytes usando as chaves de rodada w (ja expandidas). */
void cifrarBloco(const uint8_t entrada[16], uint8_t saida[16], uint8_t w[NUM_PALAVRAS][4]) {
  uint8_t estado[4][4];
  blocoParaEstado(entrada, estado);

  addRoundKey(estado, w, 0);              /* rodada 0: so a chave 0 */

  for (int rodada = 1; rodada <= 10; rodada++) {
    subBytes(estado);
    shiftRows(estado);
    if (rodada != 10) {                   /* a rodada final NAO tem MixColumns */
      mixColumns(estado);
    }
    addRoundKey(estado, w, rodada);
  }

  estadoParaBloco(estado, saida);
}

/* Decifra 1 bloco: as inversas, na ordem inversa, chaves de 10 ate 0. */
void decifrarBloco(const uint8_t entrada[16], uint8_t saida[16], uint8_t w[NUM_PALAVRAS][4]) {
  uint8_t estado[4][4];
  blocoParaEstado(entrada, estado);

  addRoundKey(estado, w, 10);             /* desfaz o fim da rodada 10 */

  for (int rodada = 9; rodada >= 0; rodada--) {
    invShiftRows(estado);
    invSubBytes(estado);
    addRoundKey(estado, w, rodada);
    if (rodada != 0) {                    /* a chave 0 nao veio depois de um MixColumns */
      invMixColumns(estado);
    }
  }

  estadoParaBloco(estado, saida);
}


/* ==========================================================================
 * PKCS#7 E MODO ECB
 * ========================================================================== */

/* Acrescenta PKCS#7: de 1 a 16 bytes, todos com o valor da quantidade.
 * Se a mensagem ja tem tamanho multiplo de 16, entra um bloco inteiro de 0x10
 * (assim o receptor SEMPRE sabe quanto remover).
 * Retorna o tamanho final (multiplo de 16).                                 */
int adicionarPadding(const uint8_t *mensagem, int tamanho, uint8_t *saida) {
  int falta = 16 - (tamanho % 16);        /* sempre da entre 1 e 16 */
  memcpy(saida, mensagem, tamanho);
  memset(saida + tamanho, falta, falta);  /* 'falta' bytes com o valor 'falta' */
  return tamanho + falta;
}

/* Remove PKCS#7. Confere se o padding e valido (se nao for, a chave estava
 * errada ou os dados chegaram corrompidos). Retorna o tamanho original ou -1. */
int removerPadding(const uint8_t *dados, int tamanho) {
  if (tamanho == 0 || tamanho % 16 != 0) {
    return -1;
  }

  int padding = dados[tamanho - 1];       /* o ultimo byte diz quantos sao */
  if (padding < 1 || padding > 16) {
    return -1;
  }

  for (int i = 1; i <= padding; i++) {    /* todos tem que ter o mesmo valor */
    if (dados[tamanho - i] != padding) {
      return -1;
    }
  }
  return tamanho - padding;
}

/* ECB: cifra cada bloco de 16 bytes de forma independente, com a mesma chave.
 * (Por isso blocos iguais geram cifrados iguais - o problema do ECB.)       */
void cifrarECB(const uint8_t *entrada, uint8_t *saida, int tamanho, uint8_t w[NUM_PALAVRAS][4]) {
  for (int i = 0; i < tamanho; i += 16) {
    cifrarBloco(&entrada[i], &saida[i], w);
  }
}

void decifrarECB(const uint8_t *entrada, uint8_t *saida, int tamanho, uint8_t w[NUM_PALAVRAS][4]) {
  for (int i = 0; i < tamanho; i += 16) {
    decifrarBloco(&entrada[i], &saida[i], w);
  }
}


/* ==========================================================================
 * CHAVE A PARTIR DAS MATRICULAS
 * --------------------------------------------------------------------------
 * 8 ultimos digitos da matricula A + 8 ultimos da B (completa com '0' a
 * esquerda se tiver menos de 8). Cada caractere vira seu codigo ASCII.
 * Ex.: "20231001" + "20231002" -> 32 30 32 33 31 30 30 31 32 30 32 33 ...
 * (a matricula deve ser escrita so com numeros)                              */
void pegarUltimos8(const char *matricula, uint8_t saida[8]) {
  int falta = 8 - (int)strlen(matricula); /* > 0: matricula curta; < 0: longa */
  for (int i = 0; i < 8; i++) {
    saida[i] = (i < falta) ? '0' : matricula[i - falta];
  }
}

void montarChave(const char *matriculaA, const char *matriculaB, uint8_t chave[16]) {
  pegarUltimos8(matriculaA, &chave[0]);   /* bytes 0 a 7  */
  pegarUltimos8(matriculaB, &chave[8]);   /* bytes 8 a 15 */
}


/* ==========================================================================
 * VALIDACAO (FIPS-197, Apendices B e C.1) E AVALANCHE
 * ========================================================================== */

/* Cifra e decifra os vetores oficiais. Retorna 1 se tudo bateu. */
int validarFIPS197() {
  /* { chave, texto claro, cifrado esperado } */
  const uint8_t vetores[2][3][16] = {
    { /* Apendice B */
      {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c},
      {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34},
      {0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32} },
    { /* Apendice C.1 */
      {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f},
      {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff},
      {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a} }
  };

  for (int t = 0; t < 2; t++) {
    uint8_t w[NUM_PALAVRAS][4], cifrado[16], decifrado[16];
    expandirChave(vetores[t][0], w);
    cifrarBloco(vetores[t][1], cifrado, w);
    decifrarBloco(cifrado, decifrado, w);
    if (memcmp(cifrado, vetores[t][2], 16) != 0 || memcmp(decifrado, vetores[t][1], 16) != 0) {
      return 0;
    }
  }
  return 1;
}

/* Conta quantos bits sao diferentes entre dois vetores (efeito avalanche).
 * O XOR deixa 1 onde os bits diferem; popcount conta esses 1. */
int contarBitsDiferentes(const uint8_t *a, const uint8_t *b, int tamanho) {
  int total = 0;
  for (int i = 0; i < tamanho; i++) {
    total += __builtin_popcount(a[i] ^ b[i]);
  }
  return total;
}

#endif /* AES128_H */
