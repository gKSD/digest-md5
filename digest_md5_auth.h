
#ifndef DIGEST_MD5_AUTH_H_
#define DIGEST_MD5_AUTH_H_
#include "mpop_string.h"

struct digest_md5_auth_request
{
    //digest-challenge params
    mpop_string realm; //host or one of those (the first) from digest challenge
    mpop_string nonce;
    mpop_string stale;
    mpop_string charset;
    mpop_string algorithm;

    char auth_param;
    mpop_string auth_param_value;

    struct token_t *qop_list; //list of qop from server
    mpop_string qop; //the chosen one

    struct token_t *cipher_list;//list from server
    mpop_string cipher; //the chosen one

    int maxbuf;
    bool maxbuf_found;
    int client_maxbuf;

    //digest-response params
    mpop_string cnonce;
    mpop_string digest_uri;
    mpop_string authzid;

    //if needed
    mpop_string enc_password;
    mpop_string enc_username;
    mpop_string enc_realm;

    char *dest_host_pos;
    long int nonce_count; //first is 00000001

    char response_value[33];
    int response_value_size;
};

struct token_t
{
    char *string;
    struct token_t *ptr;
};

void init_digest_md5_auth_request(struct digest_md5_auth_request *auth_request);
void free_digest_md5_auth_request(struct digest_md5_auth_request *auth_request);

int get_server_challenge_params(const char *host, const char *digest_challenge, int digest_challenge_size, 
                                            struct digest_md5_auth_request *auth_request);
int form_client_response_on_server_challenge(const char *host, const char *username, const char *password,
                                                mpop_string *response, struct digest_md5_auth_request *auth_request);
int make_response_value(struct digest_md5_auth_request *auth_request);
void make_digest_uri(const char *host, struct digest_md5_auth_request *auth_request);
int make_cnonce_random_string(char *cnonce, int cnonce_size);

#endif
