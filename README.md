# AES-128 em dois ESP32 via UART

Trabalho prático de Segurança de Sistemas de Computação (IFMT).
AES-128 implementado do zero (sem biblioteca de criptografia), modo ECB com PKCS#7.
A placa A cifra a mensagem da dupla e envia pela UART2; a placa B decifra e mostra o texto.

## Ligação (UART2, 115200 bps, 8N1)

| Placa A        | Placa B        |
|----------------|----------------|
| GPIO17 (TX2)   | GPIO16 (RX2)   |
| GPIO16 (RX2)   | GPIO17 (TX2)   |
| GND            | GND            |
