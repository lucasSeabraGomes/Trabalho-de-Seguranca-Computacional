/*trabalho de Lucas Seabra Gomes Oliveira-170039951*/
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>


/*fun�ao de expans�o retirada de https://docs.huihoo.com/doxygen/openssl/1.0.1c/rsa__oaep_8c_source.html*/
int PKCS1_MGF1(unsigned char* mask, long len,
    const unsigned char* seed, long seedlen, const EVP_MD* dgst)
{
    long i, outlen = 0;
    unsigned char cnt[4];
    EVP_MD_CTX* c;
    unsigned char md[EVP_MAX_MD_SIZE];
    int mdlen;
    int rv = -1;

    c = EVP_MD_CTX_create();
    mdlen = EVP_MD_size(dgst);
    if (mdlen < 0)
        goto err;
    for (i = 0; outlen < len; i++)
    {
        cnt[0] = (unsigned char)((i >> 24) & 255);
        cnt[1] = (unsigned char)((i >> 16) & 255);
        cnt[2] = (unsigned char)((i >> 8)) & 255;
        cnt[3] = (unsigned char)(i & 255);
        if (!EVP_DigestInit_ex(c, dgst, NULL)
            || !EVP_DigestUpdate(c, seed, seedlen)
            || !EVP_DigestUpdate(c, cnt, 4))
            goto err;
        if (outlen + mdlen <= len)
        {
            if (!EVP_DigestFinal_ex(c, mask + outlen, NULL))
                goto err;
            outlen += mdlen;
        }
        else
        {
            if (!EVP_DigestFinal_ex(c, md, NULL))
                goto err;
            memcpy(mask + outlen, md, len - outlen);
            outlen = len;
        }
    }
    rv = 0;
err:
    EVP_MD_CTX_destroy(c);
    return rv;
}
void gerar_chaves(){
#pragma warning(disable : 4996)
    int funcao;
    int i;
    char usuario[50];
    FILE* arquivos;
    printf("Digite o nome para ser apresentado na assinatura\n");
    scanf_s("%s", usuario, 50);
    getchar();
    usuario[strlen(usuario) + 1] = 0;
    unsigned char e_char[128];
    unsigned char n_char[128];
    unsigned char d_char[128];
    BIGNUM* e = BN_new();
    BN_rand(e, 256, 100000, 1024);
    RSA* rsa = RSA_new();
    RSA_generate_key_ex(rsa, 1024, e, NULL);
    const BIGNUM* n_rsa = RSA_get0_n(rsa);
    const BIGNUM* e_rsa = RSA_get0_e(rsa);
    const BIGNUM* d_rsa = RSA_get0_d(rsa);
    BN_bn2lebinpad(e_rsa, e_char, 128);
    BN_bn2lebinpad(n_rsa, n_char, 128);
    BN_bn2lebinpad(d_rsa, d_char, 128);
    /*salva o e em um arquivo especifico*/
    usuario[strlen(usuario)] = 'E';
    fopen_s(&arquivos, usuario, "w");
    for (i = 0; i < 128; i++) {
        fprintf(arquivos, "%02x", e_char[i]);
    }
    fclose(arquivos);
    /*concluido*/
    /*salva o N em um arquivo especifico*/
    usuario[strlen(usuario) - 1] = 'N';
    fopen_s(&arquivos, usuario, "w");
    for (i = 0; i < 128; i++) {
        fprintf(arquivos, "%02x", n_char[i]);
    }
    fclose(arquivos);
    /*concluido*/
    /*salva d em um arquivo especifico*/
    usuario[strlen(usuario) - 1] = 'D';
    fopen_s(&arquivos, usuario, "w");
    for (i = 0; i < 128; i++) {
        fprintf(arquivos, "%02x", d_char[i]);
    }
    fclose(arquivos);
    /*concluido*/

    RSA_free(rsa);
    BN_free(e);
    printf("Usuario adicionado\n");
};
void gerar_assinatura() {
    errno_t err;
    unsigned int despejo_temporario[128];
    int funcao;
    unsigned int i;
    char usuario[50];
    FILE* arquivos;
    unsigned char d_char[128];
    printf("Digite o usuario que assinar�\n");
    scanf_s("%s", usuario, 50);
    getchar();
    /*puxando o d*/
    usuario[strlen(usuario) + 1] = 0;
    usuario[strlen(usuario)] = 'D';
    err=fopen_s(&arquivos, usuario, "r");
    if (err != 0)
    {
        printf("Nome do arquivo incorreto");
        return;
    }
    for (i = 0; i < 128; i++) {
        fscanf(arquivos, "%02x", &despejo_temporario[i]);
        d_char[i]=despejo_temporario[i];
        
    }
    fclose(arquivos);


    BIGNUM* d_key = BN_new();
    BN_lebin2bn(d_char, 128, d_key);
    /*concluindo a busca do d*/
    /*puxando o n*/
    unsigned char n_cha[128];
    usuario[strlen(usuario) - 1] = 'N';
    err=fopen_s(&arquivos, usuario, "r");
    if (err != 0)
    {
        printf("Nome do arquivo incorreto");
        return;
    }
    for (i = 0; i < 128; i++) {
        fscanf(arquivos, "%02x", &despejo_temporario[i]);
        n_cha[i] = despejo_temporario[i];
    }
    fclose(arquivos);
    BIGNUM* n_ke = BN_new();
    BN_lebin2bn(n_cha, 128, n_ke);
    /*concluindo a busca do n*/
    BIGNUM* omega = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    char mess1[64]; /*mensagem a ser assinada + k1 zeros tamanho= n-k0*/
    unsigned char r[32];/*r usado no OEAP tamanho = k0*/
    unsigned char x[64];
    unsigned char x_reduzido[32];
    unsigned char y[32];
    /*pading para assinatura*/
    RAND_bytes(r, sizeof(r));
    printf("Digite uma mensagem:\n");
    scanf_s("%[^\n]s", mess1, 64);
    getchar();
    for (i = strlen(mess1); i < 64; i++)
    {
        mess1[i] = 0;
    }
    char r_expandido[64];
    for (i = 0; i < 32; i++)
    {
        r_expandido[i] = r[i];
    }
    for (i = 32; i < 64; i++)
    {
        r_expandido[i] = 0;
    }
    const unsigned char seed[2] = "\0";
    PKCS1_MGF1(reinterpret_cast<unsigned char*>(r_expandido), 64, seed, 1, EVP_sha512());
    for (i = 0; i < 64; i++)
    {
        x[i] = r_expandido[i] ^ mess1[i];
    }
    SHA256(x, 32, x_reduzido);
    for (i = 0; i < 32; i++)
    {
        y[i] = x_reduzido[i] ^ r[i];
    }
    unsigned char pading[96];

    for (i = 0; i < 64; i++)
    {
        pading[i] = x[i];
    }
    for (i = 0; i < 32; i++)
    {
        pading[i + 64] = y[i];
    }
    /*fim do pading para assinatura*/
    /*Realizando a assinatura rsa ao pading*/
    BIGNUM* menspading = BN_new();
    BN_lebin2bn(pading, 96, menspading);
    BN_mod_exp(omega, menspading, d_key, n_ke, ctx);

    BN_free(menspading);

    BN_free(n_ke);

    BN_free(d_key);

    BN_CTX_free(ctx);
    /*Concluida a assinatura rsa ao pading*/
    /*Salvando a mensagem*/
    char nome[50];
    printf("Digite um nome para o arquivo onde a mensagem ser� salva:\n");
    scanf_s("%[^\n]s", nome, 40);
    getchar();
    fopen_s(&arquivos, nome, "w");
    fwrite(mess1, 1, 64, arquivos);
    fclose(arquivos);

    /*concluindo o salvamento*/
    /*salvando a assinatura*/
    nome[strlen(nome) + 3] = '\0';
    nome[strlen(nome) + 1] = 'S';
    nome[strlen(nome) + 2] = 'S';
    nome[strlen(nome)] = 'A';

    unsigned char omega_char[128];

    BN_bn2lebinpad(omega, omega_char, 128);
    BN_free(omega);
    fopen_s(&arquivos, nome, "w");

    for (i = 0; i < 128; i++)
    {
        fprintf(arquivos, "%02x", omega_char[i]);
    }

    fclose(arquivos);
    printf("Assinatura realizada\n");
    /*concluindo o salvamento*/
};
void verificar_assinatura() {
    errno_t err;
    unsigned int despejo_temporario[128];
    int funcao;
    int i;
    char usuario[50];
    FILE* arquivos;
    unsigned char e_char[128];
    unsigned char n_char[128];
    printf("Digite o usuario da qual a assinatura sera verificada\n");
    scanf_s("%s", usuario, 50);

    getchar();
    /*puxando o e*/
    usuario[strlen(usuario) + 1] = 0;
    usuario[strlen(usuario)] = 'E';
    err=fopen_s(&arquivos, usuario, "r");
    if (err != 0)
    {
        printf("Nome do arquivo incorreto");
        return;
    }
    for (i = 0; i < 128; i++) {
        fscanf(arquivos, "%02x", &despejo_temporario[i]);
        e_char[i]=despejo_temporario[i];
    }
    fclose(arquivos);
    BIGNUM* e_key = BN_new();
    BN_lebin2bn(e_char, 128, e_key);
    /*concluindo a busca do e*/
    /*puxando o n*/
    usuario[strlen(usuario) - 1] = 'N';
    err=fopen_s(&arquivos, usuario, "r");
    if (err != 0)
    {
        printf("Nome do arquivo incorreto");
        return;
    }
    for (i = 0; i < 128; i++) {
        fscanf(arquivos, "%02x", &despejo_temporario[i]);
        n_char[i]=despejo_temporario[i];
    }
    fclose(arquivos);


    BIGNUM* n_key = BN_new();
    BN_lebin2bn(n_char, 128, n_key);

    /*concluindo a busca do n*/
     /*lendo a mensagem*/
    char mess1[64];
    char nome[50];
    printf("Digite um nome para o arquivo da mensagem que ser� verificada:\n");
    scanf_s("%[^\n]s", nome, 40);
    getchar();
    err=fopen_s(&arquivos, nome, "r");
    if (err != 0)
    {
        printf("Nome do arquivo incorreto");
        return;
    }
    fread(mess1, 1, 64, arquivos);
    fclose(arquivos);
    /*concluindo a leitura*/
    /*lendo a assinatura*/
    nome[strlen(nome) + 3] = '\0';
    nome[strlen(nome) + 1] = 'S';
    nome[strlen(nome) + 2] = 'S';
    nome[strlen(nome)] = 'A';
    unsigned char omega_char[128];
    err=fopen_s(&arquivos, nome, "r");
    if (err != 0)
    {
        printf("Nome do arquivo incorreto");
        return;
    }
    for (i = 0; i < 128; i++) {
        fscanf(arquivos, "%02x", &despejo_temporario[i]);
        omega_char[i] = despejo_temporario[i];
    }
    fclose(arquivos);
    /*concluindo a leitura*/
    /*Desfazer a assinatura usando e*/
    BIGNUM* omega = BN_new();
    BN_lebin2bn(omega_char, 128, omega);
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* temporario = BN_new();
    BN_mod_exp(temporario, omega, e_key, n_key, ctx);
    BN_CTX_free(ctx);
    BN_free(omega);
    BN_free(n_key);
    BN_free(e_key);
    unsigned char pading[96];
    BN_bn2lebinpad(temporario, pading,96);
    BN_free(temporario);
    /*desfazer pading*/
    unsigned char r_expandido[64];
    unsigned char x[64];
    unsigned char x_reduzido[32];
    for (i = 0; i < 64; i++)
    {
        x[i] = pading[i];
    }
    SHA256(x, 32, x_reduzido);
    for (i = 0; i < 32; i++)
    {
        r_expandido[i] = x_reduzido[i] ^ pading[64 + i];
    }
    for (i = 32; i < 64; i++)
    {
        r_expandido[i] = 0;
    }
    const unsigned char seed[2] = "\0";
    PKCS1_MGF1(reinterpret_cast<unsigned char*>(r_expandido), 64, seed, 1, EVP_sha512());
    char teste[64];
    for (i = 0; i < 64; i++)
    {
        teste[i] = r_expandido[i] ^ x[i];
    }
    if (strcmp(mess1, teste) == 0)
    {
        printf("A mensagem: %s\nFoi assinada pelo usuario em quest�o.\n", teste);
    }
    else{ 
        printf("Esta mensagem n�o foi assinada pelo usuario em quest�o.\n"); 
    }
    /*fim do pading*/
};


int main()
{
#pragma warning(disable : 4996)
    int funcao;
    char usuario[50];
    printf("Digite 0 para sair. \nDigite 1 para checar assinaturas \nDigite 2 para assinar\nDigite 3 para cadastrar assinatura\n");
    scanf_s("%i", &funcao);
    getchar();
    FILE* arquivos;
    while (funcao != 0) {


        if (funcao == 1) {
            /*fun��o criada pelo aluno :Lucas Seabra Gomes Oliveira-170039951*/
            verificar_assinatura();
        }
        
        if (funcao == 2) {
            /*fun��o criada pelo aluno :Lucas Seabra Gomes Oliveira-170039951*/
            gerar_assinatura();
        }


        if (funcao == 3) {
            /*fun��o criada pelo aluno :Lucas Seabra Gomes Oliveira-170039951*/
            gerar_chaves();

        }


        printf("\nDigite 0 para sair. \nDigite 1 para checar assinaturas \nDigite 2 para assinar\nDigite 3 para cadastrar assinatura\n");
        scanf_s(" %i", &funcao);
        getchar();

    }
    return 0;
}
