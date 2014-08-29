#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <strings.h>
#include <stdbool.h> 
#include <stddef.h>
#include "mpop_string.h"

//MD5 hash from rfc
//#include "global.h"
#include "digest_md5_auth.h"
//#include "qqq_md5.h"
//MD5 hash from rfc


int main(int argc, char *argv[])
{
    /*
    char qqq[] = "qwertyuiop[asdfghjkl;zxcvbnm,.qwertyuiokjhgfdsxcvbhj";
    int qqq_len = strlen(qqq);
    printf("\n\n\n\nqqq: %s, qqq_len: %i\n", qqq, qqq_len);
    char new_str1[10];
    char * ptr_new_str1 = new_str1;
    memset(ptr_new_str1, 0, 10);
    strncpy(ptr_new_str1, qqq, 9);
    printf("ptr_new_str1: %s, ptr_new_str1_len: %i\n", ptr_new_str1, strlen(ptr_new_str1));
*/

    //char host[] = "yandex.ru";
    //char host[] = ".ru";
    
    char host[] = "aqaa.bbb.ccc.imap.yandex.ru";

    char username[] = "SOFIA";
    //char password[] = "abracadabra";
    char password[] = "secret";
    int client_maxbuf = 34676;

    char digest_challenge[] = "realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",qop=\"auth\",algorithm=md5-sess,charset=utf-8";
    const int digest_challenge_size = strlen(digest_challenge);

    char digest_challenge1[] = "realm=elwood.innosoft.com,nonce=\"OA6MG9tEQGm2hh\",qop=\"auth\",algorithm=md5-sess,charset=utf-8";
    const int digest_challenge_size1 = strlen(digest_challenge1);

    char digest_challenge2[] = "realm=\"elwood.innosoft.com\"";
    const int digest_challenge_size2 = strlen(digest_challenge2);

    char digest_challenge3[] = "realm=elwood.innosoft.com";
    const int digest_challenge_size3 = strlen(digest_challenge3);

    char digest_challenge4[] = "nonce=\"OA6MG9tEQGm2hh\",maxbuf=123345,qop=\"auth-int\",algorithm=md5-sess,charset=utf-8";
    const int digest_challenge_size4 = strlen(digest_challenge4);

    char digest_challenge5[] = "realm=\"yandex.com\",nonce=\"OA6MG9tEQGm2hh\",maxbuf=123345,qop=\"auth-int\",algorithm=md5-sess";
    const int digest_challenge_size5 = strlen(digest_challenge5);

    if(argc < 2)
    {
        printf("Too low arguments\n");
        return 0;
    }
    int len = strlen(argv[1]);
    argv[1][len - 2] = '\0';
 
    if(strlen(argv[1]) >=2 && strncmp(argv[1], "//", 2) == 0)
    {
        printf("\n ****************************************** %s ******************************************\n", argv[1]);
        return 0;
    }

    const int digest_challenge_size6 = strlen(argv[1]);


    mpop_string realm, nonce;
    mpop_string stale, auth_param_value;
    mpop_string charset, algorithm;

    char auth_param;
    struct token_t *qop = NULL;
    struct token_t *cipher = NULL;

    int maxbuf;
    long int nc = 1;

    mpop_string response;
    init_string(&response);
    //char response[4096];
    //memset(response, 0, 4096);


    //snprintf(server_answer, server_answer_size, "%s", r);
    init_string(&realm);     init_string(&nonce);
    init_string(&stale);     init_string(&charset); 
    init_string(&algorithm); init_string(&auth_param_value);
    
    int res = get_server_challenge_params(host, argv[1], digest_challenge_size6, &realm,&nonce, &qop,
                                            &stale, &maxbuf, &charset, &algorithm, &cipher, &auth_param, &auth_param_value);
   
    if(res == -1)
    {
        printf("Aborted get_server_challenge_params\n\n");
        free_string(&realm);
        free_string(&nonce);
        free_string(&charset);
        free_string(&algorithm);
        free_string(&response);
        for(struct token_t *p = qop, *tmp; p != NULL;)
        {
            tmp = p;
            p = p->ptr;
            free(tmp->string);
            free(tmp);
        }
        for(struct token_t *p = cipher, *tmp; p != NULL;)
        {
            tmp = p;
            p = p->ptr;
            free(tmp->string);
            free(tmp);
        }
        return 0;
    }

    printf("\n");

    char qop1[] = "auth";
    char cipher1[] = "";
    
    
    form_client_response_on_server_challenge(host, username, password, &response, &realm, &nonce, qop1,
                                            &stale, maxbuf, &charset, &algorithm, cipher1, &auth_param, &auth_param_value, client_maxbuf, nc);

    free_string(&realm);
    free_string(&nonce);
    free_string(&charset);
    free_string(&algorithm);
    free_string(&response);

    for(struct token_t *p = qop, *tmp; p != NULL;)
    {
        tmp = p;
        p = p->ptr;
        free(tmp->string);
        free(tmp);
    }
    for(struct token_t *p = cipher, *tmp; p != NULL;)
    {
        tmp = p;
        p = p->ptr;
        free(tmp->string);
        free(tmp);
    }
    return 0; 
}
