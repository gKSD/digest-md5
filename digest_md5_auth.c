
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
#include "digest_md5_auth.h"
#include "mailbox.h"
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
                free(tmp->string);
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
        if(*maxbuf <= 0)
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
            printf("Invalid \"charset\", only utf-8 charset is allowed\n");
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
                free(tmp->string);
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
    printf("KSD get_server_challenge_params\n");
    /*char *cursor;
    mpop_string decoded_server_challenge;
    init_string(&decoded_server_challenge); 
    if(!is_decoded_from_base64)
    {
        decoder_state state;
        init_state(&state);
        cursor = (char *) digest_challenge;
        if(*cursor == '+') cursor++;
        while(*cursor == ' ') cursor++;
        decode_base64(&decoded_server_challenge, cursor, &state);
    }*/

    char *cursor = (char *) digest_challenge;
    printf("cursor: %s\n", cursor);
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

    //free_string(&decoded_server_challenge);
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

int make_response_value(const char *qop, const mpop_string *username_in_charset, const mpop_string *passwd_in_charset, const mpop_string *realm_in_charset, const mpop_string *nonce, const char *cnonce, const mpop_string *digest_uri, const long int nc, char *response, int response_size)
{
    if(response_size != 33)
    {
        printf("response-value size must be 33 byte");
        return -1;
    }
    
    //LOWER CASE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    char A1[33], A2[33], login_passw[33]; 
    MD5_CTX ctx;
    
    //forming hash of "login:realm:password" string
    printf("!!! %s:%s:%s\n", username_in_charset->string,realm_in_charset->string,passwd_in_charset->string);
    MD5Init(&ctx);
    MD5Update(&ctx, username_in_charset->string, username_in_charset->size);
    if(realm_in_charset->size > 0)
    {
        MD5Update(&ctx, ":", 1);
        MD5Update(&ctx, realm_in_charset->string, realm_in_charset->size);
    }

    MD5Update(&ctx, ":", 1);
    MD5Update(&ctx, passwd_in_charset->string, passwd_in_charset->size);
    MD5End(&ctx, login_passw);
    printf("login_passw: %s\n", login_passw);

    //forming A1
    MD5Init(&ctx);
    MD5Update(&ctx, login_passw, strlen(login_passw));
    MD5Update(&ctx, ":", 1);
    MD5Update(&ctx, nonce->string, nonce->size);
    MD5Update(&ctx, ":", 1);
    MD5Update(&ctx, cnonce, strlen(cnonce));
    /*if(authzid->size > 0)
    {
        MD5Update(&ctx, ":", 1);
        MD5Update(&ctx, authzid->string, authzid->size);
    }*/
    MD5End(&ctx, A1);
    printf("A1: %s\n", A1);

    //forming A2
    MD5Init(&ctx);
    MD5Update(&ctx, "AUTHENTICATE:", 13);
    MD5Update(&ctx, digest_uri->string, digest_uri->size);
    if(strcmp(qop, "auth-int") == 0 || strcmp(qop, "auth-conf") == 0)
    {
        printf("Is auth-int or auth-conf\n");
        MD5Update(&ctx, ":00000000000000000000000000000000", 33);
    }
    MD5End(&ctx, A2);
    printf("A2: %s\n", A2);

    //forming final md5 hash
    MD5Init(&ctx);
    MD5Update(&ctx, A1, 32);
    MD5Update(&ctx, ":", 1);
    MD5Update(&ctx, nonce->string, nonce->size);
    MD5Update(&ctx, ":", 1);
    char tmp[9];
    snprintf(tmp, 9, "%08x", nc);
    MD5Update(&ctx, tmp, 8);
    MD5Update(&ctx, ":", 1);
    MD5Update(&ctx, cnonce, strlen(cnonce));
    MD5Update(&ctx, ":", 1);
    MD5Update(&ctx, qop, strlen(qop));
    MD5Update(&ctx, ":", 1);
    MD5Update(&ctx, A2, 32);
    MD5End(&ctx, response);
    printf("KD: %s\n", response);
    
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

    /*if(charset->size)
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
    }*/

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
    make_response_value(qop, &enc_username, &enc_password, &enc_realm, nonce, cnonce, &digest_uri, nc, response_value, 33);
    printf("response_value: %s, response_value: %i\n", response_value, strlen(response_value));

    memset(ss, 0, 4096);
    snprintf(ss, 4096, "username=\"%s\",nonce=\"%s\",cnonce=\"%s\",nc=%08x,qop=%s,digest-uri=\"%s\",response=%s", enc_username.string, nonce->string, cnonce, nc, qop, digest_uri.string, response_value);

    if(response->size) add_char(response, ',');
    add_string(response, ss);

    /*if(client_maxbuf != 65535)
    {
        if(response->size) add_char(response, ',');
        add_string(response, "maxbuf=");
        sprintf(ss, "%i", maxbuf);
        add_string(response, ss);
    }*/
   
    if(strcmp(qop, "auth-conf") == 0)
    {
        //TODO: support different ciphers
    }

    free_string(&digest_uri);
    free_string(&enc_username);
    free_string(&enc_password);

    printf("RESPONSE: %s\n", response->string);
    return 1; //OK
}

