#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <stdbool.h> 
#include <stddef.h>

struct token_t
{
    char *string;
    struct token_t *ptr;
};

int parse_string(char *str, struct token_t **qop)
{
    struct token_t *current_qop;
    char * pch;
    int pch_len;
    printf ("Splitting string \"%s\" into tokens:\n",str);
    pch = strtok (str," ,\t");
    while (pch != NULL)
    {
        pch_len = strlen(pch);

        if(*qop == NULL)
            current_qop = *qop = (struct token_t *)malloc(sizeof(struct token_t)); 
        else
            current_qop = current_qop->ptr = (struct token_t *)malloc(sizeof(struct token_t));
        current_qop->string = (char *)malloc(pch_len + 1);
        snprintf(current_qop->string, pch_len + 1, "%s", pch);
        current_qop->ptr = NULL;

        pch = strtok (NULL, " ,\t");
    }
    return 0;
}


bool is_in_list(struct token_t *list, const char *str)
{
        if(strlen(str) == 0) return false;
        for(struct token_t *p = list; p != NULL; p = p->ptr)
        {
            printf("list->string: %s\n", p->string);
            if(strcmp(p->string, str) == 0) return true;
        }
        return false;
}


int func(int *b)
{
    printf("b  == %i\n", *b);
    return 1;
}

int main()
{
    char str[] = "auth,auth-int,qqq,auth-conf";
    struct token_t *qop = NULL;
    int qop_size = 0;

    qop_size = parse_string(str, &qop);

    for(struct token_t *p = qop; p != NULL;)
    {
        printf("p: %s\n", p->string);
        if(strcmp(p->string, "qqq") == 0)
        {
            struct token_t *tmp = p;
            p = p->ptr;
            if(qop == tmp) qop = p;
            free(tmp);
            if(qop == NULL)
                printf("qop is NULL\n");

        }
        else
            p = p->ptr;
    }

    for(struct token_t *p = qop; p != NULL; p= p->ptr)
        printf("p: %s\n", p->string);

    if(is_in_list(qop, "auth")) printf("YES \n");
    if(!is_in_list(qop, "qwerty")) printf("NO \n");

    for(struct token_t *p = qop, *tmp; p != NULL;)
    {
        tmp = p;
        p = p->ptr;
        free(tmp);
    }


    int a = 5;
    func(&a);

    return 0;
}
