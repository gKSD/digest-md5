
#ifndef STRSZ
#define STRSZ(str) (str),(sizeof(str)-1)
#endif

#include <stdio.h>

#include <string.h>
#include <strings.h>
#include <stdbool.h> 
#include <stddef.h>
//#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdlib.h>
#include <ctype.h>


#include <limits.h>

#include "mpop_string.h"

//MD5 hash from rfc
//#include "global.h"
#include "md5.h"
//#include "qqq_md5.h"
//MD5 hash from rfc

void generate_random_string(char *s, const int slen)
{
    //srand(time(0) + i);
    struct timeval tv;
    gettimeofday (&tv, NULL);
    srandom (getpid() ^ tv.tv_usec);
    const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    for (int i = 0; i < slen - 1; ++i)
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    s[slen - 1] = '\0';
    printf("generate_random_string, slen: %i, s: %s, strlen(s): %i\n", slen, s, strlen(s));
} 

int get_server_challenge_params(const char *host, const char *server_answer, int server_answer_size, mpop_string *realm, mpop_string *nonce,
                                mpop_string *qop, mpop_string *stale, int *maxbuf,
                                mpop_string  *charset, mpop_string *algorithm, mpop_string *cipher, mpop_string *auth_param)
{
    char *ptr , *cursor = (char *)server_answer, *right;
    
    if(ptr = strstr(cursor, "realm="))
    {
        ptr += 6;
        if (*ptr != '"') 
        {
            printf("Error, realm not well-formed! \n");
            return -1; //not well-formed realm-value
        }
        ptr++;
        right = ptr;
        printf("realm, right: %s, ptr: %s\n", right, ptr);
        while (right && *right && *right != '"' )
            right++;
        ptrdiff_t realm_size = right - ptr;
        add_stringn(realm,ptr,realm_size);
        printf("KSD realm: %s, realm_size.size: %i, realm_size: %i\n", realm->string, realm->size, realm_size);
    }
    else
    {
        //Form our realm
        printf("ImapXS: client forms realm\n");
        //add_string(realm, host);
        add_string(realm, "");
    }
    printf("realm: %s, realm->size: %i\n", realm->string, realm->size);

    //S: realm="elwood.innosoft.com",nonce="OA6MG9tEQGm2hh",qop="auth",algorithm=md5-sess,charset=utf-8
    if(ptr = strstr(cursor, "nonce="))
    {
        ptr += 6;
        if (*ptr != '"')
        {
            printf("Error, nonce not well-formed! \n");
            return -1;
        }
        ptr++;
        right = ptr;
        printf("nonce, right: %s, ptr: %s\n", right, ptr);
        while (right && *right && *right != '"')
            right++;
        ptrdiff_t nonce_size = right - ptr;
        add_stringn(nonce, ptr, nonce_size);
        printf("KSD nonce: %s, nonce_size.size: %i, nonce_size: %i\n", nonce->string, nonce->size, nonce_size);
    }
    else
    {
        printf("ImapXS: server challenge doesn't contain nonce, abort authentication\n");
        return -1; //ABORT AUTH
    }

    if(ptr = strstr(cursor, "qop="))
    {
        ptr += 4;
        if (*ptr != '"')
        {
            printf("Error, qop-options not well-formed! \n");
            return -1;
        }
        ptr++;
        int ptr_len = strlen(ptr);
        if(ptr_len >= 8 && strncmp(ptr, "auth-int", 8) == 0) add_stringn(qop, ptr, 8);
        else if(ptr_len >= 9 && strncmp(ptr, "auth-conf", 9) == 0) 
        {
            //add_stringn(qop, ptr, 9);

            //TODO: support this qop-option
            printf("Temprorary unsupported qop-option, abort auth");
            return -1;
        }
        else if(ptr_len >= 4 && strncmp(ptr, "auth", 4) == 0) add_stringn(qop, ptr, 4);
        else 
        {
            printf("Invalid qop-options value\n");
            return -1; //ABORT AUTH
        }
        printf("KSD qop-options: %s, qop_size.size: %i\n", qop->string, qop->size);
    }
    else
    {
        printf("qop-options default value = auth\n");
        add_string(qop, "auth");
        printf("KSD qop-options: %s, qop_size.size: %i\n", qop->string, qop->size);
    }

    if((ptr = strstr(cursor, "maxbuf=")) && (qop->size == 8 && strncmp(qop->string, "auth-int", 8) == 0 || qop->size == 9 && strncmp(qop->string, "auth-conf", 9) == 0))
    {
        ptr += 7;
        char ss[10];
        memset(ss, 0, 10);
        right = ptr;
        for(int i = 0; right && *right && isdigit(*right); right++)
            ss[i++] = *right;
        //printf("ss: %s\n", ss);
        if(right == ptr) 
        {
            printf("Invalid maxbuf\n");
            return -1;
        }
        *maxbuf = atoi(ss);
        if(ptr =strstr(ptr, "maxbuf"))
        {
            printf("Multiple instances of \"maxbuf\", abort auth\n");
            return -1; //ABORT AUTH
        }
        printf("Maxbuf: %i\n", *maxbuf);
    }
    else
        *maxbuf = 65535;

    if(ptr = strstr(cursor, "charset="))
    {
        ptr += 8;
        if(strlen(ptr) >= 5 && strncmp(ptr, "utf-8", 5) == 0)
            add_stringn(charset, ptr, 5);
        else
        {
            printf("Invalid \"charset\", abort auth\n");
            return -1;
        }
        printf("charset, right: %s, ptr: %s\n", right, ptr);
        if(ptr = strstr(ptr, "charset"))
        {
            printf("Multiple instances of \"charset\", abort auth\n");
            return -1; //ABORT AUTH
        }
    }
    else
    {
        //default == ASCII
    }

    if(ptr = strstr(cursor, "algorithm="))
    {
        ptr += 10;
        if(strlen(ptr) >= 8 && strncmp(ptr, "md5-sess", 8) == 0)
            add_stringn(algorithm, ptr, 8);
        else
        {
            printf("Invalid \"algorithm\", abort auth\n");
            return -1;
        }
        if(ptr = strstr(ptr, "algorithm"))
        {
            printf("Multiple instances of \"algorithm\", abort auth\n");
            return -1;
        }
    }
    else
    {
        printf("\"algorithm\" is not present in server challenge, abort auth\n");
        return -1;
    }

    if((ptr = strstr(cursor, "cipher=")) && (qop->size == 9 && strncmp(qop->string, "auth-conf", 9) == 0))
    {
        ptr += 7;
        if (*ptr != '"') 
        {
            printf("Error, cipher not well-formed! \n");
            return -1; //not well-formed realm-value
        }
        int ptr_len = strlen(ptr);
        if(ptr_len >= 3 && strncmp(ptr, "des", 3) == 0) add_stringn(cipher, ptr, 3);
        else if(ptr_len >= 4 && strncmp(ptr, "3des", 4) == 0) add_stringn(cipher, ptr, 4);
        else if(ptr_len >= 3 && strncmp(ptr, "rc4", 3) == 0) add_stringn(cipher, ptr, 3);
        else if(ptr_len >= 6 && strncmp(ptr, "rc4-40", 6) == 0) add_stringn(cipher, ptr, 6);
        else if(ptr_len >= 6 && strncmp(ptr, "rc4-56", 6) == 0) add_stringn(cipher, ptr, 6);
        else 
        {
            printf("ImapXS: invalid cipher-opts value\n");
            return -1; //ABORT AUTH
        }

        if(ptr = strstr(ptr, "cipher"))
        {
            printf("Multiple instances of \"cipher\", abort auth\n");
            return -1;
        }

    }

    //stale !!!
    return 1; //OK
}

void decode_to_utf8(const char *str, mpop_string *decoded_str)
{
        add_string(decoded_str, str);
    //Заглушка
}

int make_cnonce_random_string(char *cnonce, int cnonce_size)
{
    if (cnonce_size == 0)
    {
        printf("error: the nonce-value string must not empty\n");
        return -1;
    }
    if(cnonce_size <= 8)
        printf("warning: the size of nonce-value string is too short\n");
        //your message shoul contain at least ** synmbols

    generate_random_string(cnonce, cnonce_size);
    return 1;
}

//DEBUG
char * my_strrchr(const char *cp, int ch)
{
    char *save, *prev_save;
    char c;
    for (prev_save = save = (char *) 0; (c = *cp); cp++) {
        if (c == ch)
        {
            prev_save = save;
            save = (char *) cp;
        }
    }
    if (!prev_save) return save;
    return prev_save;
}

void  make_digest_uri(const char *host, mpop_string *digest_uri)
{
    add_string(digest_uri,"imap/");
    add_string(digest_uri, host);

    //new
    char *ptr = (char *)host + strlen(host), *save = (char *) 0;
    short int dot_counter = 0;

    for(; dot_counter <= 1 && ptr != host; ptr--)
    {
        if(*ptr == '.')
        {
            save = ptr;
            dot_counter++;
        }
    }
    if (dot_counter == 2)
    {
        add_char(digest_uri, '/');
        add_string(digest_uri, ++save);
    }
    //new

    /*char *save, *prev_save, *ptr = (char *)host;
    char c, ch = '.';
    for (prev_save = save = (char *) 0; (c = *ptr); ptr++) {
        if (c == ch)
        {
            prev_save = save;
            save = (char *) ptr;
        }
    }
    if(prev_save)
    {
        prev_save++;
        add_char(digest_uri, '/');
        add_string(digest_uri, prev_save);
    }*/
    printf("*** URI, ptr: %s\n", ptr);
}

int make_response_value(const mpop_string *qop, const mpop_string *username_in_charset, const mpop_string *passwd_in_charset, const mpop_string *realm_in_charset, const mpop_string *nonce, const char *cnonce, const mpop_string *digest_uri, char *response, int response_size)
{
    if(response_size < 33)
    {
        printf("response-value size must be 33 byte");
        return -1;
    }
    //LOWER CASE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    mpop_string A1, A2, KD;
    init_string(&A1);
    init_string(&A2);
    init_string(&KD);
    
    int ss_len = username_in_charset->size + passwd_in_charset->size + realm_in_charset->size + 3;
    char *ss = (char *)malloc(ss_len);
    if(!ss)
    {
        printf("Can't allocate memory\n");
        free_string(&A1);
        free_string(&A2);
        return -1;
    }
    
    if(realm_in_charset->size)
        snprintf(ss, ss_len, "%s:%s:%s", username_in_charset->string, realm_in_charset->string, passwd_in_charset->string);
    else
        snprintf(ss, ss_len, "%s::%s", username_in_charset->string, passwd_in_charset->string);

    printf("ss: %s, ss_len: %i, strlen(ss) = %i\n", ss, ss_len, strlen(ss));
    char digest[33];
    MD5Data((unsigned char *)ss, ss_len - 1, digest);
    printf("ss: %s, strlen(digest)\n", digest, strlen(digest));
 
    //form A1
    //
    //if(authzid->size)
    /*{
        add_string(&A1, digest);
        add_char(&A1,':');
        add_stringn(&A1, nonce->string, nonce->size);
        add_char(&A1,':');
        add_stringn(&A1, cnonce->string, cnonce->size);
        add_char(&A1,':');
        add_stringn(&A1, authzid->string, authzid->size);
    }*/
    //else
    //{
    add_string(&A1, digest);
    add_char(&A1,':');
    add_stringn(&A1, nonce->string, nonce->size);
    add_char(&A1,':');
    add_string(&A1, cnonce);
    //}

    //form A2
    add_string(&A2, "AUTHENTICATE:");
    add_stringn(&A2, digest_uri->string, digest_uri->size);
    if(strcmp(qop->string, "auth-conf") == 0 || strcmp(qop->string, "auth-int") == 0 )
        add_string(&A2, ":00000000000000000000000000000000");

    printf("A1: %s, A2: %s\n", A1.string, A2.string);

    
    //form KD
    memset(digest, 0, 33);
    MD5Data((unsigned char *)A1.string, A1.size, digest);
    printf("A1 digest: %s, strlen(A1 digest): %i\n", digest, strlen(digest));
    add_string(&KD, digest);
    
    add_char(&KD,':');
    add_stringn(&KD, nonce->string, nonce->size);
    add_char(&KD,':');
    add_string(&KD, cnonce);
    add_char(&KD,':');
    add_stringn(&KD, qop->string, qop->size);
    add_char(&KD,':');

    memset(digest, 0, 33);
    MD5Data((unsigned char *)A2.string, A2.size, digest);
    printf("A2 digest: %s, strlen(A2 digest): %i\n", digest, strlen(digest));
    add_string(&KD, digest);

    printf("KD: %s\n", KD.string);

    MD5Data((unsigned char *)KD.string, KD.size, response); 

    free(ss);
    free_string(&A1);
    free_string(&A2);
    free_string(&KD);
    return 1;
}

int form_client_response_on_server_challenge(const char *host, const char *username, const char *password, mpop_string *response, const mpop_string *realm, const mpop_string *nonce, 
                                             const mpop_string *qop, const mpop_string *stale, int maxbuf, const mpop_string *charset, 
                                             const mpop_string *algorithm, const mpop_string *cipher, const mpop_string *auth_param, int client_maxbuf, long int nc)
{
    bool is_utf8 = false;
    mpop_string enc_password, enc_username, enc_realm;
    init_string(&enc_password);
    init_string(&enc_username);
    init_string(&enc_realm);

    if(charset->size)
    {
        if (strcasecmp(charset->string, "ISO-8859-1") != 0 && strcasecmp(charset->string, "US-ASCII") != 0)
        {
            if(strcmp(charset->string, "utf-8") != 0)
            {
                printf("Imap.xs: invalid charset");
                return -1;
            }
            add_string(response, "charset=");
            add_string(response, charset->string);
            is_utf8 = true;
        }
    }

    if(is_utf8) //decode only username and password and realm-value
    {
        decode_to_utf8(username, &enc_username);
        decode_to_utf8(password, &enc_password);
        if(realm->size)
            decode_to_utf8(realm->string, &enc_realm);
    }
    else
    {
        add_string(&enc_username, username);
        add_string(&enc_password, password);
        if(realm->size)
            add_string(&enc_realm, realm->string);
    }

    if(realm->size)
    {
        if(response->size) add_char(response, ',');
        add_string(response, "realm=\"");
        add_string(response, realm->string);
        add_char(response, '\"');
    }

    const int cnonce_size = 15;
    char ss[4096], response_value[33];
    char cnonce[cnonce_size];
    mpop_string digest_uri;
    init_string(&digest_uri);
    
    memset(cnonce, 0, cnonce_size);
    if(make_cnonce_random_string(cnonce, cnonce_size) == -1)
    {
        free_string(&enc_username);
        free_string(&enc_password);
        free_string(&digest_uri);
        return -1;
    }

    make_digest_uri(host, &digest_uri);
    memset(response_value, 0, 33);
    make_response_value(qop, &enc_username, &enc_password, &enc_realm, nonce, cnonce, &digest_uri, response_value, 33);
    printf("response_value: %s, response_value: %i\n", response_value, strlen(response_value));

    memset(ss, 0, 4096);
    snprintf(ss, 4096, "username=\"%s\",nonce=\"%s\",cnonce=\"%s\",nc=%08x,qop=%s,digest-uri=\"%s\",response=%s", enc_username.string, nonce->string, cnonce, nc, qop->string, digest_uri.string, response_value);

    if(response->size) add_char(response, ',');
    add_string(response, ss);

    if(client_maxbuf != 65535)
    {
        if(response->size) add_char(response, ',');
        add_string(response, "maxbuf=");
        sprintf(ss, "%i", maxbuf);
        add_string(response, ss);
    }
   
    if(strcmp(qop->string, "auth-conf") == 0)
    {
        //TODO: support different ciphers
    }

    free_string(&digest_uri);
    free_string(&enc_username);
    free_string(&enc_password);

    printf("\n\n\nResult response: %s\n", response->string);
    return 1; //OK
}

void func(char *qq, int ll)
{
            char cut_token[16];
            memset(cut_token,0,16);
            strncpy(cut_token, qq, ll > 15? 15: ll);
            printf("cut_token: %s, ll: %i  '\\n' \n", cut_token, ll);
}

int main()
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
    char password[] = "abracadabra";
    int client_maxbuf = 34676;

    char server_answer[] = "realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",qop=\"auth\",algorithm=md5-sess,charset=utf-8";
    const int server_answer_size = strlen(server_answer);

    char server_answer1[] = "realm=elwood.innosoft.com,nonce=\"OA6MG9tEQGm2hh\",qop=\"auth\",algorithm=md5-sess,charset=utf-8";
    const int server_answer_size1 = strlen(server_answer1);

    char server_answer2[] = "realm=\"elwood.innosoft.com\"";
    const int server_answer_size2 = strlen(server_answer2);

    char server_answer3[] = "realm=elwood.innosoft.com";
    const int server_answer_size3 = strlen(server_answer3);

    char server_answer4[] = "nonce=\"OA6MG9tEQGm2hh\",maxbuf=123345,qop=\"auth-int\",algorithm=md5-sess,charset=utf-8";
    const int server_answer_size4 = strlen(server_answer4);

    char server_answer5[] = "nonce=\"OA6MG9tEQGm2hh\",maxbuf=123345,qop=\"auth-int\",algorithm=md5-sess,charset=utf-8";
    const int server_answer_size5 = strlen(server_answer5);


    mpop_string realm, nonce;
    mpop_string qop, stale;
    mpop_string charset, algorithm;
    mpop_string cipher, auth_param;

    int maxbuf;
    long int nc = 1;

    mpop_string response;
    init_string(&response);
    //char response[4096];
    //memset(response, 0, 4096);


    //snprintf(server_answer, server_answer_size, "%s", r);
    init_string(&realm);   init_string(&nonce);
    init_string(&qop);     init_string(&stale);
    init_string(&charset); init_string(&algorithm);
    init_string(&cipher);  init_string(&auth_param);
    get_server_challenge_params(host, server_answer5, server_answer_size5, &realm,&nonce, &qop, 
                                            &stale, &maxbuf, &charset, &algorithm, &cipher, &auth_param);
   
    
    form_client_response_on_server_challenge(host, username, password, &response, &realm, &nonce, &qop,
                                            &stale, maxbuf, &charset, &algorithm, &cipher, &auth_param, client_maxbuf, nc);

    free_string(&realm);
    free_string(&nonce);
    free_string(&qop);
    free_string(&charset);
    free_string(&algorithm);
    free_string(&cipher);
    free_string(&response);
    //{
        //printf("1 realm yes\n");
        //free(realm);
    //}
    //else printf("1 realm no\n");


    /*get_server_challenge_params(server_answer1, server_answer_size1, realm, realm_value, nonce, nonce_value, qop_options, 
                                            qop_list, qop_value, stale, maxbuf, maxbuf_value, charset, algorithm, cipher_opts, 
                                            cipher_value, auth_param);
    if(realm) 
    {
        printf("2 realm yes\n");
        //free(realm);
    }
    else
        printf("2 realm no\n");

    get_server_challenge_params(server_answer2, server_answer_size2, realm, realm_value, nonce, nonce_value, qop_options, 
                                            qop_list, qop_value, stale, maxbuf, maxbuf_value, charset, algorithm, cipher_opts, 
                                            cipher_value, auth_param);
    //if(realm) free(realm);

    get_server_challenge_params(server_answer3, server_answer_size3, realm, realm_value, nonce, nonce_value, qop_options, 
                                            qop_list, qop_value, stale, maxbuf, maxbuf_value, charset, algorithm, cipher_opts, 
                                            cipher_value, auth_param);
    //if(realm) free(realm);*/


    
    /*char tt[15];
    generate_random_string(tt, 15);
    printf("\nget_random(): %s", tt);
   
    char sss[10];
    snprintf(sss, 10, "aaaa");
    printf("\n\nsss: %s,strlen(s): %i\n", sss, strlen(sss));
    */
    
    return 0; 
}









