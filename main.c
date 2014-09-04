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

    char username[] = "sofia";
    //char password[] = "abracadabra";
    char password[] = "123456";

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


    struct digest_md5_auth_request auth_request;
    init_digest_md5_auth_request(&auth_request);
    mpop_string response;
    init_string(&response);
    //char response[4096];
    //memset(response, 0, 4096);

    
    int res = get_server_challenge_params(host, argv[1], digest_challenge_size6, &auth_request);
   
    if(res == -1)
    {
        printf("Aborted get_server_challenge_params\n\n");
        free_digest_md5_auth_request(&auth_request);
        free_string(&response);
        return 0;
    }

    printf("\n");

    add_string(&auth_request.qop, "auth");

    form_client_response_on_server_challenge(host, username, password, &response, &auth_request);
    free_digest_md5_auth_request(&auth_request);
    free_string(&response);
    return 0; 
}
