
#ifndef DIGEST_MD5_AUTH_H_
#define DIGEST_MD5_AUTH_H_
struct token_t
{
    char *string;
    struct token_t *ptr;
};

int get_server_challenge_params(const char *host, const char *digest_challenge, int digest_challenge_size, mpop_string *realm, 
                                                mpop_string *nonce, struct token_t **qop, mpop_string *stale, int *maxbuf, 
                                                mpop_string  *charset, mpop_string *algorithm, struct token_t **cipher, 
                                                char *auth_param, mpop_string *auth_param_value);

int form_client_response_on_server_challenge(const char *host, const char *username, const char *password, mpop_string *response, 
                                                const mpop_string *realm, const mpop_string *nonce, const char *qop, 
                                                const mpop_string *stale, int maxbuf, const mpop_string *charset,
                                                const mpop_string *algorithm, const char *cipher, const char *auth_param, 
                                                const mpop_string *auth_param_value, int client_maxbuf, long int nc);
int make_response_value(const char *qop, const mpop_string *username_in_charset, const mpop_string *passwd_in_charset, 
                                                const mpop_string *realm_in_charset, const mpop_string *nonce, const char *cnonce, 
                                                const mpop_string *digest_uri, char *response, int response_size);
void  make_digest_uri(const char *host, mpop_string *digest_uri, char *dest_host_pos);
int make_cnonce_random_string(char *cnonce, int cnonce_size);

#endif
