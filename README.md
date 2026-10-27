# YubiVault

Cofre portátil para Windows que cifra arquivos e pastas e só os abre com a sua **YubiKey**. Um único `.exe`, sem instalação e sem precisar de administrador: dá para levar no pendrive.

> **Status:** em desenvolvimento. Ainda não há versão pronta para uso.

## Como funciona

- **YubiKey como chave.** O app usa o modo HMAC-SHA1 challenge-response (slot 2) da YubiKey. O segredo nunca sai da chave, e cada abertura pede um toque no botão.
- **Senha opcional.** Pode ser combinada com a YubiKey, como segundo fator, caso alguém pegue a chave e o cofre juntos.
- **Recuperação.** Ao criar o cofre, o app mostra um código de recuperação para imprimir e guardar. Uma segunda YubiKey pode ser registrada depois, sem cifrar tudo de novo.
- **Criptografia em camadas.** Cada arquivo passa por AES-256-GCM e depois por XChaCha20-Poly1305, com chaves independentes derivadas por HKDF-SHA256. Uma falha futura em um dos algoritmos não basta para expor os dados.
- **Cofre em pasta.** O cofre é uma pasta comum (pendrive, HD, OneDrive, Google Drive). Por fora não aparecem nomes, pastas nem estrutura; só blobs cifrados e um índice cifrado.

## Roteiro

1. [x] Desenho técnico
2. [ ] Núcleo de criptografia e linha de comando, com testes
3. [ ] Interface gráfica de cofre (WPF)
4. [ ] Executável único e portátil para Windows x64

## Requisitos

- Windows 10 ou 11, 64 bits
- YubiKey série 5 (testado com a YubiKey 5 NFC)

## Tecnologia

C# e .NET 10, [SDK oficial da Yubico](https://github.com/Yubico/Yubico.NET.SDK), [NSec](https://nsec.rocks/) (libsodium) para XChaCha20-Poly1305 e Argon2id, e a criptografia nativa do Windows para AES-256-GCM.

## Licença

[GPLv3](LICENSE). O YubiVault é um projeto independente e não é afiliado à Yubico. YubiKey é marca registrada da Yubico AB.
