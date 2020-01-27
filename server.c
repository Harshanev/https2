#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <fcntl.h>
#include <signal.h>
#define FAIL    -1
#define MAXSZ 5000
SSL_CTX *ctx;
int server;
int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}
SSL_CTX* InitServerCTX(void)
{
    SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = TLSv1_2_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}
void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}
void process_rec_send(SSL *newsockfd,char file_name[100]){
        int fd,i,j;
        char msg[MAXSZ];
        memset(msg,'\0',MAXSZ);
        fd = open(file_name,O_RDONLY);
        char line[120];
        if (fd == -1) {
  //       perror("r1"); 
                close(fd);
                fd = open("err.html",O_RDONLY);
                printf("fd%d\n",fd);
        }
        int bytesread;
        i = 0;
        bytesread = read (fd, &msg[i], 1);
        char c = msg[i];
        while (c != EOF && bytesread > 0) {
                i++;
                bytesread = read (fd, &msg[i], 1);
                c = msg[i];
        }

        msg[i]='\0';
        SSL_write(newsockfd, "HTTP/1.1 200 OK\r\n",16);
        SSL_write(newsockfd, "Server : Web Server in C\r\n\r\n",25);
/*
     send(newsockfd,"HTTP/1.1 200 OK\n",16,0);
     send(newsockfd, "Content-length: 151\n", 19,0); ///here still is a problem mentioned above
     send(newsockfd, "Content-Type: text/html\n\n", 25,0); */
        i = 0;
        j = 0;
        while (msg[i] != '\0' ) {
                line[j] = msg[i];
                j++;
                i++;
                if ( j == 100 ) {
                        SSL_write(newsockfd,line,j);
                        j = 0;
                }
        }
        SSL_write(newsockfd,line,j);
        printf("Receive and set:%s\n",msg);
        close(fd);
}
void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
    char *ptr;
    int i;
    char first_line[100];
    char buf[1024] = {0};
    int sd,bytes;
    if ( SSL_accept(ssl) == FAIL ) {    /* do SSL-protocol accept */
             ERR_print_errors_fp(stderr);
        }
    else
    {
        ShowCerts(ssl);        /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        buf[bytes] = '\0';
        printf("Client msg: \"%s\"\n", buf);
        i = 0;
        while ((first_line[i] = buf[i]) != '\n')
                i++;
        first_line[i] = '\0';
        ptr = strstr(first_line, " HTTP/");
        if (ptr == NULL) {
            printf("NOT HTTP !\n");
            process_rec_send(ssl,"http.txt");
        } else {
                *ptr = 0;
                 ptr = NULL;
        }
        if (strncmp(first_line, "GET ", 4) == 0) {
               ptr = first_line + 5;
        }
        if (ptr == NULL) {
           printf("Unknown Request ! \n");
        }
        else {
            printf("ptr length %zd\n",strlen(ptr));
            if (ptr[strlen(ptr) - 1] == '/') {
               strcat(ptr, "index.html");
            }
         }
         strcpy(first_line, ptr);
         printf("First Line%s\n",first_line);
         process_rec_send(ssl,first_line);
   }
   sd = SSL_get_fd(ssl);       /* get socket connection */
   SSL_free(ssl);         /* release SSL state */
   close(sd);          /* close connection */
}
void  INThandler(int sig)
{
     char  c;

     signal(sig, SIG_IGN);
     printf("OUCH, did you hit Ctrl-C?\n"
            "Do you really want to quit? [y/n] ");
     c = getchar();
     if (c == 'y' || c == 'Y') {
        SSL_CTX_free(ctx);         /* release context */
        close(server);          /* close server socket */
        exit(0);
     }
     else
          signal(SIGINT, INThandler);
}
int main(int count, char *Argc[])
{
    char *portnum;
//Only root user have the permsion to run the server
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    if ( count != 2 )
    {
        printf("Usage: %s <portnum>\n", Argc[0]);
        exit(0);
    }
    signal(SIGINT, INThandler);
    // Initialize the SSL library
    portnum = Argc[1];
    SSL_library_init();
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */
    server = OpenListener(atoi(portnum));    /* create server socket */
    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        int client;
        while ((client = accept(server, (struct sockaddr*)&addr, &len)) < 0) 
          ;
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
        Servlet(ssl);         /* service connection */
   }
}
