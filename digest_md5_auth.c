
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
//

#define MD5_DIGEST_LENGTH 16

void init_digest_md5_auth_request(struct digest_md5_auth_request *auth_request)
{
    init_string(&auth_request->realm);
    init_string(&auth_request->nonce);
    init_string(&auth_request->stale);
    init_string(&auth_request->charset);
    init_string(&auth_request->algorithm);
    init_string(&auth_request->auth_param_value);
    init_string(&auth_request->qop);
    init_string(&auth_request->cipher);
    init_string(&auth_request->cnonce);
    init_string(&auth_request->digest_uri);
    init_string(&auth_request->authzid);
    init_string(&auth_request->enc_password);
    init_string(&auth_request->enc_username);
    init_string(&auth_request->enc_realm);

    int size = 16;
    allocate_string(&auth_request->cnonce, size);
    auth_request->cnonce.size = size;

    auth_request->qop_list = NULL;
    auth_request->cipher_list = NULL;
    auth_request->maxbuf = 65535; //default
    auth_request->maxbuf_found = false;
    auth_request->client_maxbuf = 65535;
    auth_request->dest_host_pos = NULL;
    auth_request->nonce_count = 1; //first is 00000001
    auth_request->response_value_size = 33;

    memset(auth_request->response_value, 0, auth_request->response_value_size);
}

void free_digest_md5_auth_request(struct digest_md5_auth_request *auth_request)
{
    free_string(&auth_request->realm);
    free_string(&auth_request->nonce);
    free_string(&auth_request->stale);
    free_string(&auth_request->charset);
    free_string(&auth_request->algorithm);
    free_string(&auth_request->auth_param_value);
    free_string(&auth_request->qop);
    free_string(&auth_request->cipher);
    free_string(&auth_request->cnonce);
    free_string(&auth_request->digest_uri);
    free_string(&auth_request->authzid);
    free_string(&auth_request->enc_password);
    free_string(&auth_request->enc_username);
    free_string(&auth_request->enc_realm);

    for(struct token_t *p = auth_request->qop_list, *tmp; p != NULL;)
    {
        tmp = p;
        p = p->ptr;
        free(tmp->string);
        free(tmp);
    }

    for(struct token_t *p = auth_request->cipher_list, *tmp; p != NULL;)
    {
        tmp = p;
        p = p->ptr;
        free(tmp->string);
        free(tmp);
    }
}

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

int process_param(char *param, char *param_value, int is_quoted_param_value,
                                struct digest_md5_auth_request *auth_request)
{
    if(strcmp(param, "realm") == 0)
    {
        if (!is_quoted_param_value)
        {
            printf("Error, \"realm\" not well-formed! \n");
            return -1; //not well-formed realm-value
        }
        if(auth_request->realm.size != 0)
            return 1; //multiple instances of realm value are possible; use the first one
        add_string(&auth_request->realm, param_value);
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
        if(auth_request->nonce.size != 0)
        {
            printf("Multiple instances of \"nonce\", abort auth\n");
            return -1;
        }
        add_string(&auth_request->nonce, param_value);
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
        if(auth_request->qop_list != NULL)
        {
            printf("Multiple instances of \"qop\", abort auth\n");
            return -1;
        }
        parse_string_into_tokens(param_value, &auth_request->qop_list);
        for(struct token_t *p = auth_request->qop_list, *prev = p; p != NULL;)
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
                if(tmp == auth_request->qop_list) auth_request->qop_list = p;
                free(tmp->string);
                free(tmp);
                if(auth_request->qop_list == NULL)
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
        if(auth_request->maxbuf_found)
        {
            printf("Multiple instances of \"maxbuf\", abort auth\n");
            return -1;
        }
        if(is_quoted_param_value && strlen(param_value) == 0)
        {
            printf("Error, \"maxbuf\" value is empty\n");
            return -1;
        }
        auth_request->maxbuf = atoi(param_value);
        if(auth_request->maxbuf <= 0)
        {
            printf("Invalid \"maxbuf\" value\n");
            return -1;
        }
        auth_request->maxbuf_found = true;
    }
    else if(strcmp(param, "charset") == 0)
    {
        if(auth_request->charset.size != 0)
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
            add_string(&auth_request->charset, param_value);
        else
        {
            printf("Invalid \"charset\", only utf-8 charset is allowed\n");
            return -1;
        }
    }
    else if(strcmp(param, "algorithm") == 0)
    {
        if(auth_request->algorithm.size != 0)
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
            add_string(&auth_request->algorithm, param_value);
        else
        {
            printf("Invalid \"algorithm\", abort auth\n");
            return -1;
        }
    }
    else if(strcmp(param, "cipher") == 0)
    {
        if(auth_request->cipher_list != NULL)
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

        parse_string_into_tokens(param_value, &auth_request->cipher_list);
        for(struct token_t *p = auth_request->cipher_list, *prev = p; p != NULL;)
            if(strcmp(p->string, "des") != 0 && strcmp(p->string, "3des") != 0 &&  strcmp(p->string, "rc4") != 0
                && strcmp(p->string, "rc4-40") != 0 && strcmp(p->string, "rc4-56") != 0)
            {
                struct token_t *tmp = p;
                p = p->ptr;
                prev->ptr = p;
                if(auth_request->cipher_list == tmp) auth_request->cipher_list = p;
                free(tmp->string);
                free(tmp);
                if(auth_request->cipher_list == NULL)
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
        auth_request->auth_param = c;
        if (!(strlen(param_value) == 1 && is_token(*param_value)) 
            && !(is_quoted_param_value && is_valid_TEXT(param_value)))
        {
            printf("Invalid auth-param value\n");
            return -1;
        }
        add_string(&auth_request->auth_param_value, param_value);
    }
    else if (strcmp(param, "stale") == 0)
    {
        if(auth_request->stale.size != 0)
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
            add_string(&auth_request->stale, param_value);
        else
        {
            printf("Invalid stale value\n");
            return -1;
        }
    }

    return 1;
}

int get_server_challenge_params(const char *host, const char *digest_challenge, int digest_challenge_size,
                                    struct digest_md5_auth_request *auth_request)
{
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

    auth_request->maxbuf = 0;

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
        if(process_param(param, param_value, is_quoted_param_value, auth_request) == -1)
        {
            free(param);
            free(param_value);
            return -1;
        }
    }
    free(param);
    free(param_value);

    if(auth_request->realm.size != 0)
    {
        strcat(command_log, "realm: ");
        strcat(command_log, auth_request->realm.string);
        is_first = false;
    }
    
    if(auth_request->nonce.size == 0)
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
    strcat(command_log, auth_request->nonce.string);

    if(auth_request->qop_list == NULL)
    {
        auth_request->qop_list = (struct token_t *)malloc(sizeof(struct token_t));
        auth_request->qop_list->string = (char *)malloc(5);
        sprintf(auth_request->qop_list->string, "auth");
        auth_request->qop_list->ptr = NULL;
    }

    strcat(command_log, ", qop: ");
    is_first = true;
    for(struct token_t *p = auth_request->qop_list; p != NULL; p = p->ptr)
    {
        if(is_first) is_first = false;
        else strcat(command_log, ",");
        strcat(command_log, p->string);
    }

    if(auth_request->maxbuf_found 
        && strcmp(auth_request->qop_list->string, "auth") == 0 
        && auth_request->qop_list->ptr == NULL)
    {
        printf("\"maxbuf\" must be present only when using \"auth-int\" or \"auth-conf\"\n");
        return -1;
    }
    else if(is_in_list(auth_request->qop_list, "auth-int") 
                || is_in_list(auth_request->qop_list, "auth-conf"))
    {
        if(!auth_request->maxbuf_found)
            auth_request->maxbuf = 65535; //default
        strcat(command_log, ", maxbuf: ");
        char buf[33];
        snprintf(buf, 33, "%i", auth_request->maxbuf);
        strcat(command_log, buf);
    }

    if(auth_request->charset.size != 0)
    {
        strcat(command_log, ", charset: ");
        strcat(command_log, auth_request->charset.string);
    }

    if(auth_request->algorithm.size == 0)
    {
        printf("\"algorithm\" is not present in server challenge, abort auth\n");
        return -1;
    }

    strcat(command_log, ", algorithm: ");
    strcat(command_log, auth_request->algorithm.string);

    if(auth_request->cipher_list != NULL && !is_in_list(auth_request->qop_list, "auth-conf"))
    {
        printf("\"cipher\" must be present only when using \"auth-conf\"\n");
        return -1;
    }
    else if(auth_request->cipher_list == NULL
        && strcmp(auth_request->qop_list->string, "auth-conf") == 0 && auth_request->qop_list->ptr == NULL)
    {
        printf("\"cipher-opts\" is not present while using auth-conf\n");
        return -1;
    }
    else if (auth_request->cipher_list != NULL)
    {
        strcat(command_log, ", cipher: ");
        is_first = true;
        for(struct token_t *p = auth_request->cipher_list; p != NULL; p = p->ptr)
        {
            if(is_first) is_first = false;
            else strcat(command_log, ",");
            strcat(command_log, p->string);
        }
    }

    if(auth_request->auth_param_value.size != 0)
    {
        strcat(command_log, ", auth_param: ");
        strcat(command_log, &auth_request->auth_param);
        strcat(command_log, ", auth_param_value: ");
        strcat(command_log, auth_request->auth_param_value.string);
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

void  make_digest_uri(const char *host, struct digest_md5_auth_request *auth_request)
{
    add_string(&auth_request->digest_uri,"imap/");
    add_string(&auth_request->digest_uri, host);

    if (host != auth_request->dest_host_pos)
    {
        add_char(&auth_request->digest_uri, '/');
        add_string(&auth_request->digest_uri, auth_request->dest_host_pos);
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

int make_response_value(struct digest_md5_auth_request *auth_request)
{
    if(auth_request->response_value_size != 33)
    {
        printf("response-value size must be 33 byte");
        return -1;
    }

    char A1[33], A2[33];
    unsigned char login_passw[MD5_DIGEST_LENGTH]; 
    MD5_CTX ctx;
    
    //forming hash of "login:realm:password" string
    MD5Init(&ctx);
    MD5Update(&ctx, auth_request->enc_username.string, auth_request->enc_username.size);
    MD5Update(&ctx, ":", 1);
    if(auth_request->enc_realm.size > 0)
    {
        printf("KSD is realm_in_charset\n");
        MD5Update(&ctx, auth_request->enc_realm.string, auth_request->enc_realm.size);
    }

    MD5Update(&ctx, ":", 1);
    MD5Update(&ctx, auth_request->enc_password.string, auth_request->enc_password.size);
    MD5Final(login_passw, &ctx);

    //forming A1
    MD5Init(&ctx);
    MD5Update(&ctx, login_passw, MD5_DIGEST_LENGTH);
    MD5Update(&ctx, ":", 1);
    MD5Update(&ctx, auth_request->nonce.string, auth_request->nonce.size);
    MD5Update(&ctx, ":", 1);
    MD5Update(&ctx, auth_request->cnonce.string, auth_request->cnonce.size);
    /*if(auth_request->authzid.size > 0)
    {
        printf("KSD is authzid\n");
        MD5Update(&ctx, ":", 1);
        MD5Update(&ctx, auth_request->authzid.string, auth_request->authzid.size);
    }*/
    MD5End(&ctx, A1);
    printf("A1: %s\n", A1);

    //forming A2
    MD5Init(&ctx);
    MD5Update(&ctx, "AUTHENTICATE:", 13);
    MD5Update(&ctx, auth_request->digest_uri.string, auth_request->digest_uri.size);
    if(strcmp(auth_request->qop.string, "auth-int") == 0 || strcmp(auth_request->qop.string, "auth-conf") == 0)
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
    MD5Update(&ctx, auth_request->nonce.string, auth_request->nonce.size);
    MD5Update(&ctx, ":", 1);
    char tmp[9];
    snprintf(tmp, 9, "%08x", auth_request->nonce_count);
    MD5Update(&ctx, tmp, 8);
    MD5Update(&ctx, ":", 1);
    MD5Update(&ctx, auth_request->cnonce.string, auth_request->cnonce.size);
    MD5Update(&ctx, ":", 1);
    MD5Update(&ctx, auth_request->qop.string, auth_request->qop.size);
    MD5Update(&ctx, ":", 1);
    MD5Update(&ctx, A2, 32);
    MD5End(&ctx, auth_request->response_value);
 
    return 1;
}

int form_client_response_on_server_challenge(const char *host, const char *username, 
                                                const char *password, mpop_string *response,
                                                struct digest_md5_auth_request *auth_request)
{
    bool is_utf8 = false;
    auth_request->dest_host_pos = get_dest_host_pos(host);

    if(auth_request->charset.size)
    {
        if(strcmp(auth_request->charset.string, "utf-8") != 0)
        {
            printf("Imap.xs: invalid charset");
            return -1;
        }
        add_string(response, "charset=");
        add_string(response, auth_request->charset.string);
        is_utf8 = true;
    }

    if(is_utf8) //decode only username and password and realm-value
    {
        decode_to_utf8(username, &auth_request->enc_username);
        decode_to_utf8(password, &auth_request->enc_password);
        if(auth_request->realm.size)
            decode_to_utf8(auth_request->realm.string, &auth_request->enc_realm);
    }
    else
    {
        add_string(&auth_request->enc_username, username);
        add_string(&auth_request->enc_password, password);
        if(auth_request->realm.size)
            add_string(&auth_request->enc_realm, auth_request->realm.string);
    }

    if(response->size) add_char(response, ',');
    if(auth_request->realm.size)
    {
        //if(response->size) add_char(response, ',');
        add_string(response, "realm=\"");
        add_string(response, auth_request->realm.string);
        add_char(response, '\"');
    }
    else
    {
        add_string(response, "realm=\"");
        add_string(response, auth_request->dest_host_pos);
        add_char(response, '\"');
    }

    char ss[4096];
    
    if(make_cnonce_random_string(auth_request->cnonce.string, auth_request->cnonce.size + 1) == -1)
        return -1;

    make_digest_uri(host, auth_request);
    memset(auth_request->response_value, 0, auth_request->response_value_size);
    make_response_value(auth_request);
    printf("response_value: %s, response_value: %i\n", auth_request->response_value, auth_request->response_value_size);

    memset(ss, 0, 4096);
    snprintf(ss,4096,"username=\"%s\",nonce=\"%s\",cnonce=\"%s\",nc=%08x,qop=%s,digest-uri=\"%s\",response=%s",
                auth_request->enc_username.string, auth_request->nonce.string, auth_request->cnonce.string,
                auth_request->nonce_count, auth_request->qop.string, auth_request->digest_uri.string, 
                auth_request->response_value);

    if(response->size) add_char(response, ',');
    add_string(response, ss);

    if(auth_request->client_maxbuf != 65535 && auth_request->client_maxbuf > 0)
    {
        if(response->size) add_char(response, ',');
        add_string(response, "maxbuf=");
        sprintf(ss, "%i", auth_request->client_maxbuf);
        add_string(response, ss);
    }
   
    if(strcmp(auth_request->qop.string, "auth-conf") == 0)
    {
        //TODO: support different ciphers
    }

    printf("RESPONSE: %s\n", response->string);
    return 1; //OK
}

