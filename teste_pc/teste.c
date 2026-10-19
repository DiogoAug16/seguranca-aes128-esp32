/* Teste no PC do aes128.h (o mesmo arquivo usado nos ESP32).
 * Compilar:  gcc -I../transmissor teste.c -o teste && ./teste
 * Confere com FIPS-197 (Apendices B e C.1) e com os valores do enunciado. */
#include <stdio.h>
#include "aes128.h"

int falhas = 0;

/* converte um caractere hexadecimal ('0'..'9', 'a'..'f', 'A'..'F') no seu valor */
int valorHex(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return 0;
}

/* converte texto hexadecimal ("3243f6...") em bytes.
 * Cada 2 caracteres viram 1 byte: "32" -> 3*16 + 2 = 0x32.
 * (Nao usa sscanf("%hhx") porque o MinGW antigo do Windows nao suporta.) */
void hexParaBytes(const char *hex, uint8_t *saida) {
  int numBytes = strlen(hex) / 2;
  for (int i = 0; i < numBytes; i++) {
    int alto  = valorHex(hex[2 * i]);
    int baixo = valorHex(hex[2 * i + 1]);
    saida[i] = alto * 16 + baixo;
  }
}

/* compara o que o codigo gerou com o valor esperado */
void confere(const char *nome, const uint8_t *obtido, const char *esperadoHex, int n) {
  uint8_t esperado[64];
  hexParaBytes(esperadoHex, esperado);
  if (memcmp(obtido, esperado, n) == 0) {
    printf("[ OK ] %s\n", nome);
  } else {
    printf("[FALHOU] %s\n", nome);
    falhas++;
  }
}

/* copia a chave da rodada r (palavras w[4r]..w[4r+3]) para 16 bytes */
void chaveDaRodada(uint8_t w[NUM_PALAVRAS][4], int r, uint8_t saida[16]) {
  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 4; j++)
      saida[i * 4 + j] = w[r * 4 + i][j];
}

void testeFips(const char *nome, const char *k, const char *p, const char *c) {
  uint8_t chave[16], claro[16], cifrado[16], decifrado[16];
  uint8_t w[NUM_PALAVRAS][4];
  hexParaBytes(k, chave);
  hexParaBytes(p, claro);
  expandirChave(chave, w);
  cifrarBloco(claro, cifrado, w);
  decifrarBloco(cifrado, decifrado, w);
  char n1[80], n2[80];
  sprintf(n1, "%s cifra", nome);
  sprintf(n2, "%s decifra", nome);
  confere(n1, cifrado, c, 16);
  confere(n2, decifrado, p, 16);
}

int main(void) {
  printf("== Vetores FIPS-197 ==\n");
  testeFips("Apendice B  ", "2b7e151628aed2a6abf7158809cf4f3c",
            "3243f6a8885a308d313198a2e0370734", "3925841d02dc09fbdc118597196a0b32");
  testeFips("Apendice C.1", "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a");
  if (!validarFIPS197()) falhas++;
  printf("[%s] validarFIPS197 (usada nas placas)\n", validarFIPS197() ? " OK " : "FALHOU");

  /* rodada 1 do Apendice B (valores dos slides), passo a passo */
  {
    uint8_t chave[16], claro[16], tmp[16];
    uint8_t w[NUM_PALAVRAS][4];
    uint8_t estado[4][4];
    hexParaBytes("2b7e151628aed2a6abf7158809cf4f3c", chave);
    hexParaBytes("3243f6a8885a308d313198a2e0370734", claro);
    expandirChave(chave, w);

    chaveDaRodada(w, 1, tmp);  confere("Chave rodada 1 (slide)", tmp, "a0fafe1788542cb123a339392a6c7605", 16);
    chaveDaRodada(w, 10, tmp); confere("Chave rodada 10 (slide)", tmp, "d014f9a8c9ee2589e13f0cc8b6630ca6", 16);

    blocoParaEstado(claro, estado);
    addRoundKey(estado, w, 0); estadoParaBloco(estado, tmp);
    confere("Apos AddRoundKey 0 (slide)", tmp, "193de3bea0f4e22b9ac68d2ae9f84808", 16);
    subBytes(estado);          estadoParaBloco(estado, tmp);
    confere("Apos SubBytes r1 (slide)", tmp, "d42711aee0bf98f1b8b45de51e415230", 16);
    shiftRows(estado);         estadoParaBloco(estado, tmp);
    confere("Apos ShiftRows r1 (slide)", tmp, "d4bf5d30e0b452aeb84111f11e2798e5", 16);
    mixColumns(estado);        estadoParaBloco(estado, tmp);
    confere("Apos MixColumns r1 (slide)", tmp, "046681e5e0cb199a48f8d37a2806264c", 16);
    addRoundKey(estado, w, 1); estadoParaBloco(estado, tmp);
    confere("Fim rodada 1 (slide)", tmp, "a49c7ff2689f352b6b5bea43026a5049", 16);

    /* as inversas desfazem as diretas */
    uint8_t antes[16], depois[16];
    estadoParaBloco(estado, antes);
    shiftRows(estado); invShiftRows(estado);
    mixColumns(estado); invMixColumns(estado);
    subBytes(estado); invSubBytes(estado);
    estadoParaBloco(estado, depois);
    printf("[%s] Inversas desfazem as transformacoes\n", memcmp(antes, depois, 16) == 0 ? " OK " : "FALHOU");
  }

  printf("\n== Exemplo do enunciado (matriculas 20231001 / 20231002) ==\n");
  {
    const char *A = "20231001";
    const char *B = "20231002";
    uint8_t chave[16];
    uint8_t w[NUM_PALAVRAS][4];
    montarChave(A, B, chave);
    expandirChave(chave, w);
    confere("Chave", chave, "32303233313030313230323331303032", 16);

    char msg[80];
    sprintf(msg, "A:%s;B:%s", A, B);
    uint8_t comPadding[96], cifrado[96], decifrado[96];
    int n = adicionarPadding((const uint8_t *)msg, strlen(msg), comPadding);
    printf("Mensagem: \"%s\" (%d bytes) -> com PKCS#7: %d bytes\n", msg, (int)strlen(msg), n);
    confere("Bloco 1 com PKCS#7", comPadding, "413a32303233313030313b423a323032", 16);
    confere("Bloco 2 com PKCS#7", comPadding + 16, "33313030320b0b0b0b0b0b0b0b0b0b0b", 16);
    cifrarECB(comPadding, cifrado, n, w);
    confere("Cifrado bloco 1", cifrado, "3a3784991ab0acaa88d5fd94cb7b74ad", 16);
    confere("Cifrado bloco 2", cifrado + 16, "cbea1d9e3e1f39da47111cf69064b166", 16);
    decifrarECB(cifrado, decifrado, n, w);
    int original = removerPadding(decifrado, n);
    decifrado[original] = '\0';
    printf("[%s] Decifrado + remove PKCS#7: \"%s\"\n",
           strcmp((char *)decifrado, msg) == 0 ? " OK " : "FALHOU", decifrado);

    /* mensagem de exatamente 16 bytes -> bloco inteiro de 0x10 */
    uint8_t p16[48];
    int n16 = adicionarPadding((const uint8_t *)"1234567890123456", 16, p16);
    printf("[%s] Mensagem de 16 bytes vira %d bytes (ultimo = 0x%02x)\n",
           (n16 == 32 && p16[31] == 0x10) ? " OK " : "FALHOU", n16, p16[31]);

    /* ECB: 3 blocos */
    uint8_t c1[16], c2[16], c3[16];
    cifrarBloco((const uint8_t *)"LIGAR LED VERDE.", c1, w);
    cifrarBloco((const uint8_t *)"DESLIGAR LED    ", c2, w);
    cifrarBloco((const uint8_t *)"LIGAR LED VERDE.", c3, w);
    confere("ECB bloco 1 LIGAR", c1, "e0c22a6f02664f487dc9528642203dec", 16);
    confere("ECB bloco 2 DESLIGAR", c2, "2b4d065ea65478b60696616244cd5070", 16);
    confere("ECB bloco 3 = bloco 1", c3, "e0c22a6f02664f487dc9528642203dec", 16);

    /* matricula curta: completa com 0 */
    uint8_t ch2[16];
    montarChave("12345", "9876543210", ch2);
    confere("Matricula curta / longa", ch2, "30303031323334353736353433323130", 16);

    /* avalanche */
    uint8_t outro[16], ch3[16];
    uint8_t w2[NUM_PALAVRAS][4];
    memcpy(ch3, chave, 16);
    ch3[0] ^= 0x01;
    expandirChave(ch3, w2);
    cifrarBloco(comPadding, outro, w2);
    printf("Avalanche (1 bit da chave): %d de 128 bits mudaram\n", contarBitsDiferentes(cifrado, outro, 16));
    uint8_t msg2[16];
    memcpy(msg2, comPadding, 16);
    msg2[0] ^= 0x01;
    cifrarBloco(msg2, outro, w);
    printf("Avalanche (1 bit da msg):   %d de 128 bits mudaram\n", contarBitsDiferentes(cifrado, outro, 16));
  }

  printf("\n%s\n", falhas ? "HOUVE FALHAS" : "TUDO CERTO");
  return falhas;
}
