
#ifndef STRSZ
#define STRSZ(str) (str),(sizeof(str)-1)
#endif

#include <stdio.h>
#include <stdlib.h>

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
#include "main.h"
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
    //printf("generate_random_string, slen: %i, s: %s, strlen(s): %i\n", slen, s, strlen(s));
}

bool is_in_list(struct token_t *list, const char *str)
{
    if(strlen(str) == 0) return false;
    for(struct token_t *p = list; p != NULL; p = p->ptr)
        if(strcmp(p->string, str) == 0) return true;
    return false;
}

int parse_string_into_tokens(char *str, struct token_t **qop)
{
    struct token_t *current_qop;
    char * pch;
    int pch_len;
    int counter = 0;
    pch = strtok (str," ,\t");
    while (pch != NULL)
    {
        pch_len = strlen(pch);

        if(*qop == NULL)
            current_qop = *qop = (struct token_t *)malloc(sizeof(struct token_t)); 
        else
            current_qop = current_qop->ptr = (struct token_t *)malloc(sizeof(struct token_t));
        counter++;
        current_qop->string = (char *)malloc(pch_len + 1);
        snprintf(current_qop->string, pch_len + 1, "%s", pch);
        current_qop->ptr = NULL;

        pch = strtok (NULL, " ,\t");
    }
    return counter;
}


bool is_CTL(char c)
{
    return (c >= 0 && c <= 31 || c == 127);
}

bool is_separator(char c)
{
    return (c == '(' || c == ')' || c == '<' || c == '>' || c == '@'
                || c == ',' || c == ';' || c == ':' || c == '\\' || c == '\"'
                || c == '/' || c == '[' || c == ']' || c == '?' || c == '='
                || c == '{' || c == '}' || c == ' ' || c == '\t');
}

bool is_token(char c)
{
    return (!is_CTL(c) && !is_separator(c));
}

bool is_valid_TEXT(const char *str)
{
    char *ptr = (char *)str;
    for (; ptr && *ptr; ptr++)
        if(*ptr != ' ' && *ptr != '\t' && is_CTL(*ptr))
            return false;
    return true;
}

int parse_next_param(char **str, char *param, char *param_value, int *is_quoted)
{
    char *cursor = (char *)*str;
    char *param_pos, *param_value_pos;
    ptrdiff_t delta;

    if(*cursor == ',')
        cursor++;
    
    *is_quoted = -1;

    while (isspace(*cursor)) cursor++;
    param_pos = cursor;
    while(cursor && *cursor && *cursor != '=' && *cursor != ',')
        cursor++;
    delta = cursor - param_pos + 1;
    if(delta == 1)
    {
        printf("Invalid digest-challenge\n");
        return -1;
    }

    snprintf(param, delta, "%s", param_pos);

    if(*cursor != '=')
    {
        printf("Invalid digest-challenge\n");
        return -1;
    }
    cursor++;
    while (isspace(*cursor)) cursor++;

    if(*cursor == '"')
    {
        param_value_pos = ++cursor;
        while(cursor && *cursor && *cursor != '"') cursor++;
        if(*cursor != '"')
        {
            printf("Invalid digest-challenge\n");
            return -1;
        }
        cursor++;
        delta = cursor - param_value_pos;
        *is_quoted = 1;
    }
    else 
    {
        param_value_pos = cursor;
        while(cursor && *cursor && *cursor != ',') cursor++;
        *is_quoted = 0;
        delta = cursor - param_value_pos + 1;
        if(delta == 1)
        {
            printf("Invalid digest-challenge, param value can't be empty\n");
            return -1;
        }
    }

    /*if(delta == 1)
    {
         printf("Invalid digest-challenge\n");
         return -1;
    }*/
    snprintf(param_value, delta, "%s", param_value_pos);

    *str = cursor;
    return 1;
}

int process_param(char *param, char *param_value, int is_quoted_param_value, mpop_string *realm, mpop_string *nonce,
                    struct token_t **qop, mpop_string *stale, int *maxbuf, int *maxbuf_found, mpop_string *charset, mpop_string *algorithm,
                    struct token_t **cipher, char *auth_param, mpop_string *auth_param_value)
{
    if(strcmp(param, "realm") == 0)
    {
        if (!is_quoted_param_value)
        {
            printf("Error, \"realm\" not well-formed! \n");
            return -1; //not well-formed realm-value
        }
        if(realm->size != 0)
            return 1; //multiple instances of realm value are possible; use the first one
        add_string(realm, param_value);
        //printf("Empty param_value was added, realm->size: %i\n", realm->size);
    }
    else if(strcmp(param, "nonce") == 0)
    {
        if (!is_quoted_param_value)
        {
            printf("Error, \"nonce\" not well-formed! \n");
            return -1;
        }
        if(strlen(param_value) == 0)
        {
            printf("Error, \"nonce\" value is empty\n");
            return -1;
        }
        if(nonce->size != 0)
        {
            printf("Multiple instances of \"nonce\", abort auth\n");
            return -1;
        }
        add_string(nonce, param_value);
    }
    else if(strcmp(param, "qop") == 0)
    {
        if (!is_quoted_param_value)
        {
            printf("Error, qop-options not well-formed! \n");
            return -1;
        }
        if(strlen(param_value) == 0)
        {
            printf("Error, \"qop\" value is empty\n");
            return -1;
        }
        if(*qop != NULL)
        {
            printf("Multiple instances of \"qop\", abort auth\n");
            return -1;
        }
        parse_string_into_tokens(param_value, qop);
        for(struct token_t *p = *qop, *prev = p; p != NULL;)
        {
            if(strcmp(p->string, "auth-conf") == 0)
            {
                //TODO: support this qop-option
                printf("Temprorary unsupported qop-option, abort auth\n");
                //return -1;
            }
            else if(strcmp(p->string, "auth") != 0 && strcmp(p->string, "auth-int") != 0)
            {
                struct token_t *tmp = p;
                p = p->ptr;
                prev->ptr = p;
                if(tmp == *qop) *qop = p;
                free(tmp);
                if(*qop == NULL)
                {
                    printf("Invalid qop-options value\n");
                    return -1;
                }
                continue;
            }
            prev = p;
            p = p->ptr;
        }
    }
    else if(strcmp(param, "maxbuf") == 0)
    {
        if(*maxbuf_found)
        {
            printf("Multiple instances of \"maxbuf\", abort auth\n");
            return -1;
        }
        if(is_quoted_param_value && strlen(param_value) == 0)
        {
            printf("Error, \"maxbuf\" value is empty\n");
            return -1;
        }
        *maxbuf = atoi(param_value);
        if(*maxbuf < 0)
        {
            printf("Invalid \"maxbuf\" value\n");
            return -1;
        }
        *maxbuf_found = 1;
    }
    else if(strcmp(param, "charset") == 0)
    {
        if(charset->size != 0)
        {
            printf("Multiple instances of \"charset\", abort auth\n");
            return -1;
        }
        if(is_quoted_param_value && strlen(param_value) == 0)
        {
            printf("Error, \"charset\" value is empty\n");
            return -1;
        }
        if(strcmp(param_value, "utf-8") == 0)
            add_string(charset, param_value);
        else
        {
            printf("Invalid \"charset\", abort auth\n");
            return -1;
        }
    }
    else if(strcmp(param, "algorithm") == 0)
    {
        if(algorithm->size != 0)
        {
            printf("Multiple instances of \"algorithm\", abort auth\n");
            return -1;
        }
        if(is_quoted_param_value && strlen(param_value) == 0)
        {
            printf("Error, \"algorithm\" value is empty\n");
            return -1;
        }
        if(strcmp(param_value, "md5-sess") == 0)
            add_string(algorithm, param_value);
        else
        {
            printf("Invalid \"algorithm\", abort auth\n");
            return -1;
        }
    }
    else if(strcmp(param, "cipher") == 0)
    {
        if(*cipher != NULL)
        {
            printf("Multiple instances of \"cipher\", abort auth\n");
            return -1;
        }
        if (!is_quoted_param_value)
        {
            printf("Error, \"cipher-opt\" not well-formed! \n");
            return -1;
        }
        if(strlen(param_value) == 0)
        {
            printf("Error, \"cipher\" value is empty\n");
            return -1;
        }

        parse_string_into_tokens(param_value, cipher);
        for(struct token_t *p = *cipher, *prev = p; p != NULL;)
            if(strcmp(p->string, "des") != 0 && strcmp(p->string, "3des") != 0 &&  strcmp(p->string, "rc4") != 0
                && strcmp(p->string, "rc4-40") != 0 && strcmp(p->string, "rc4-56") != 0)
            {
                struct token_t *tmp = p;
                p = p->ptr;
                prev->ptr = p;
                if(*cipher == tmp) *cipher = p;
                free(tmp);
                if(*cipher == NULL)
                {
                    printf("Invalid cipher-opts value\n");
                    return -1;
                }
                continue;
            }
            else 
            {
                prev = p;
                p = p->ptr;
            }
    }
    else if(strlen(param) == 1)
    {
        char c = *param;
        if(!is_token(c))
        {
            printf("Unexpected value of auth-param\n");
            return -1;
        }
        *auth_param = c;
        if (!(strlen(param_value) == 1 && is_token(*param_value)) && !(is_quoted_param_value && is_valid_TEXT(param_value)))
        {
            printf("Invalid auth-param value\n");
            return -1;
        }
        add_string(auth_param_value, param_value);
    }
    else if (strcmp(param, "stale") == 0)
    {
        if(stale->size != 0)
        {
            printf("Multiple instances of \"stale\", abort auth\n");
            return -1;
        }
        if(strlen(param_value) == 0)
        {
            printf("Error, \"stale\" value is empty\n");
            return -1;
        }
        if(strcmp(param_value, "true") == 0)
            add_string(stale, param_value);
        else
        {
            printf("Invalid stale value\n");
            return -1;
        }
    }

    return 1;
}

int get_server_challenge_params(const char *host, const char *digest_challenge, int digest_challenge_size,
                                    mpop_string *realm, mpop_string *nonce, struct token_t **qop,
                                    mpop_string *stale, int *maxbuf, mpop_string  *charset,
                                    mpop_string *algorithm, struct token_t **cipher, char *auth_param, mpop_string *auth_param_value)
{
    char *cursor = (char *)digest_challenge;
    char *param, *param_value;
    int is_quoted_param_value;

    const int max_log_size = 32768;
    char command_log[max_log_size];
    bool is_first = true;
    memset(command_log, 0, max_log_size);

    *maxbuf = 0;

    if(digest_challenge_size == 0)
    {
        printf("Empty digest-challenge from server, abort auth");
        return -1;
    }

    int maxbuf_found = 0;

    //size of param and param_value can't be more than digest_challenge_size
    param = (char *)malloc(digest_challenge_size);
    param_value = (char *)malloc(digest_challenge_size);
    if(!param || !param_value)
    {
        printf("Can't allocate memory\n");
        return -1;
    }

    printf("REQUEST: %s\n", cursor);

    while(cursor && *cursor)
    {
        memset(param, 0, digest_challenge_size);
        memset(param_value, 0, digest_challenge_size);
        if(parse_next_param(&cursor, param, param_value, &is_quoted_param_value) == -1)
        {
            free(param);
            free(param_value);
            return -1;
        }

        //printf("param: %s, param_value: %s, strlen(param_value): %i\n", param, param_value, strlen(param_value));
        if(process_param(param, param_value, is_quoted_param_value, realm, nonce, qop, stale,
                            maxbuf, &maxbuf_found, charset, algorithm, cipher, auth_param, auth_param_value) == -1)
        {
            free(param);
            free(param_value);
            return -1;
        }
    }
    free(param);
    free(param_value);

    if(realm->size != 0)
    {
        strcat(command_log, "realm: ");
        strcat(command_log, realm->string);
        is_first = false;
    }
    
    if(nonce->size == 0)
    {
        printf("\"nonce\" is not present in server challenge, abort auth\n");
        return -1;
    }
    if(is_first)
    {
        strcat(command_log, "nonce: ");
        is_first = false;
    }
    else strcat(command_log, ", nonce: ");
    strcat(command_log, nonce->string);

    if(*qop == NULL)
    {
        *qop = (struct token_t *)malloc(sizeof(struct token_t));
        (*qop)->string = (char *)malloc(5);
        sprintf((*qop)->string, "auth");
        (*qop)->ptr = NULL;
    }

    strcat(command_log, ", qop: ");
    is_first = true;
    for(struct token_t *p = *qop; p != NULL; p = p->ptr)
    {
        if(is_first) is_first = false;
        else strcat(command_log, ",");
        strcat(command_log, p->string);
    }

    if(maxbuf_found && strcmp((*qop)->string, "auth") == 0 && (*qop)->ptr == NULL)
    {
        printf("\"maxbuf\" must be present only when using \"auth-int\" or \"auth-conf\"\n");
        return -1;
    }
    else if(is_in_list(*qop, "auth-int") || is_in_list(*qop, "auth-conf"))
    {
        if(!maxbuf_found)
            *maxbuf = 65535; //default
        strcat(command_log, ", maxbuf: ");
        char buf[33];
        snprintf(buf, 33, "%i", *maxbuf);
        strcat(command_log, buf);
    }

    if(charset->size != 0)
    {
        strcat(command_log, ", charset: ");
        strcat(command_log, charset->string);
    }

    if(algorithm->size == 0)
    {
        printf("\"algorithm\" is not present in server challenge, abort auth\n");
        return -1;
    }

    strcat(command_log, ", algorithm: ");
    strcat(command_log, algorithm->string);

    if(*cipher != NULL && !is_in_list(*qop, "auth-conf"))
    {
        printf("\"cipher\" must be present only when using \"auth-conf\"\n");
        return -1;
    }
    else if(*cipher == NULL && strcmp((*qop)->string, "auth-conf") == 0 && (*qop)->ptr == NULL)
    {
        printf("\"cipher-opts\" is not present while using auth-conf\n");
        return -1;
    }
    else if (*cipher != NULL)
    {
        strcat(command_log, ", cipher: ");
        is_first = true;
        for(struct token_t *p = *cipher; p != NULL; p = p->ptr)
        {
            if(is_first) is_first = false;
            else strcat(command_log, ",");
            strcat(command_log, p->string);
        }
    }

    if(auth_param_value->size != 0)
    {
        strcat(command_log, ", auth_param: ");
        strcat(command_log, auth_param);
        strcat(command_log, ", auth_param_value: ");
        strcat(command_log, auth_param_value->string);
    }

    printf("RESULT: %s\n", command_log);
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
        //your message should contain at least ** synmbols

    generate_random_string(cnonce, cnonce_size);
    return 1;
}

char *get_dest_host_pos(const char *host)
{
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
        return ++save;
    return (char *)host;
}

void  make_digest_uri(const char *host, mpop_string *digest_uri, char *dest_host_pos)
{
    add_string(digest_uri,"imap/");
    add_string(digest_uri, host);

    if (host != dest_host_pos)
    {
        add_char(digest_uri, '/');
        add_string(digest_uri, dest_host_pos);
    }
    /*//new
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
    */
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
}

int make_response_value(const char *qop, const mpop_string *username_in_charset, const mpop_string *passwd_in_charset, const mpop_string *realm_in_charset, const mpop_string *nonce, const char *cnonce, const mpop_string *digest_uri, char *response, int response_size)
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
    if(strcmp(qop, "auth-conf") == 0 || strcmp(qop, "auth-int") == 0 )
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
    add_string(&KD, qop);
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
                                             const char *qop, const mpop_string *stale, int maxbuf, const mpop_string *charset, 
                                             const mpop_string *algorithm, const char *cipher, const char *auth_param, const mpop_string *auth_param_value, int client_maxbuf, long int nc)
{
    bool is_utf8 = false;
    char *dest_host_pos = get_dest_host_pos(host);
    mpop_string enc_password, enc_username, enc_realm;
    init_string(&enc_password);
    init_string(&enc_username);
    init_string(&enc_realm);

    if(charset->size)
    {
        printf("Charset: %s\n", charset->string);
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

    if(response->size) add_char(response, ',');
    if(realm->size)
    {
        //if(response->size) add_char(response, ',');
        add_string(response, "realm=\"");
        add_string(response, realm->string);
        add_char(response, '\"');
    }
    else
    {
        add_string(response, "realm=\"");
        add_string(response, dest_host_pos);
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

    make_digest_uri(host, &digest_uri, dest_host_pos);
    memset(response_value, 0, 33);
    make_response_value(qop, &enc_username, &enc_password, &enc_realm, nonce, cnonce, &digest_uri, response_value, 33);
    printf("response_value: %s, response_value: %i\n", response_value, strlen(response_value));

    memset(ss, 0, 4096);
    snprintf(ss, 4096, "username=\"%s\",nonce=\"%s\",cnonce=\"%s\",nc=%08x,qop=%s,digest-uri=\"%s\",response=%s", enc_username.string, nonce->string, cnonce, nc, qop, digest_uri.string, response_value);

    if(response->size) add_char(response, ',');
    add_string(response, ss);

    if(client_maxbuf != 65535)
    {
        if(response->size) add_char(response, ',');
        add_string(response, "maxbuf=");
        sprintf(ss, "%i", maxbuf);
        add_string(response, ss);
    }
   
    if(strcmp(qop, "auth-conf") == 0)
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
    char password[] = "abracadabra";
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
    struct token_t *qop;
    struct token_t *cipher;

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
        return 0;
    }

    printf("\n");
    
    
    //form_client_response_on_server_challenge(host, username, password, &response, &realm, &nonce, qop,
    //                                        &stale, maxbuf, &charset, &algorithm, cipher, &auth_param, &auth_param_value, client_maxbuf, nc);

    free_string(&realm);
    free_string(&nonce);
    free_string(&charset);
    free_string(&algorithm);
    free_string(&response);

    for(struct token_t *p = qop, *tmp; p != NULL;)
    {
        tmp = p;
        p = p->ptr;
        free(tmp);
    }
    for(struct token_t *p = cipher, *tmp; p != NULL;)
    {
        tmp = p;
        p = p->ptr;
        free(tmp);
    }
    return 0; 
}









