#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define MAX_BUFFER_SIZE 4096

int main() {
    RSA *rsa = NULL;
    FILE *publicKeyFile = NULL;
    FILE *privateKeyFile = NULL;
    unsigned char encrypted[MAX_BUFFER_SIZE];
    unsigned char decrypted[MAX_BUFFER_SIZE];
    int encryptedSize, decryptedSize;

    // Gerar chave pública e chave privada
    rsa = RSA_generate_key(2048, 65537, NULL, NULL);
    publicKeyFile = fopen("public.pem", "wb");
    privateKeyFile = fopen("private.pem", "wb");
    PEM_write_RSAPublicKey(publicKeyFile, rsa);
    PEM_write_RSAPrivateKey(privateKeyFile, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(publicKeyFile);
    fclose(privateKeyFile);

    // Carregar chave pública
    publicKeyFile = fopen("public.pem", "rb");
    rsa = PEM_read_RSAPublicKey(publicKeyFile, NULL, NULL, NULL);
    fclose(publicKeyFile);

    // Criptografar mensagem
    const char *message = "Hello, world!";
    encryptedSize = RSA_public_encrypt(strlen(message) + 1, (unsigned char *)message, encrypted, rsa, RSA_PKCS1_PADDING);
    printf("Mensagem criptografada: ");
    for (int i = 0; i < encryptedSize; i++) {
        printf("%02x", encrypted[i]);
    }
    printf("\n");

    // Carregar chave privada
    privateKeyFile = fopen("private.pem", "rb");
    rsa = PEM_read_RSAPrivateKey(privateKeyFile, NULL, NULL, NULL);
    fclose(privateKeyFile);

    // Descriptografar mensagem
    decryptedSize = RSA_private_decrypt(encryptedSize, encrypted, decrypted, rsa, RSA_PKCS1_PADDING);
    printf("Mensagem descriptografada: %s\n", decrypted);

    RSA_free(rsa);
    return 0;
}
