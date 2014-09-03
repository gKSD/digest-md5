#include <stdio.h>
#include <string.h>
#include "mpop_string.h"
#include "mailbox.h"
#include <ctype.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <stdbool.h>
#include <strings.h>
#include <signal.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <malloc.h>
#include "digest_md5_auth.h"
typedef struct {
    struct sockaddr_in addr;    // current memcached server address
    int sd;                     // socket descriptor
    char* rcv_buf;              // buffer for memcached receiving data
    char* snd_buf;              // buffer for memcached sending data
} xmemc_t;


bool is_memc_timeouted = false;

typedef void (*sig_handler)(int);

static void proc_sigalarm_simple(int signal)
{
	is_memc_timeouted = true;
}

static inline int init_alarm_handler(sig_handler handler)
{
      struct sigaction sact;
      sigset_t sset;

      if (sigemptyset (&sset) < 0) {
	    printf("XS Error: sigemptyset error\n");
    	  return -1;
      }

      sact.sa_handler = handler;
      sact.sa_flags = SA_NODEFER;  		 		/* Не блокировать SIGALRM в функции обработки этого сигнала */
      sact.sa_mask = sset;
      if (sigaction (SIGALRM, &sact, NULL) < 0) 
      {
	      printf("XS Error: sigaction error\n");
    	  return -1;
      }
      
      return 0;
}
static inline int set_timeout_once(size_t microsec)
/*
	setting timer for once operation
*/
{
      struct itimerval itvl;
      itvl.it_interval.tv_sec = 0;				// it_interval <-- следующее значение таймера
      itvl.it_interval.tv_usec = 0;
      
      itvl.it_value.tv_sec = 0;					// it_value    <-- текущее значение
      itvl.it_value.tv_usec = microsec;				// 50 micro sec * 1000 = 50 mili sec
      if (setitimer (ITIMER_REAL, &itvl, NULL) < 0) 
      {
         printf("XS Error: settimer error\n");
         return -1;
      }
      
      return 0;
}

static inline int timed_connect_remote_server(const struct sockaddr_in* addr, const char* host, int port)
{
	int sd = -1;
	int flags, connected;

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd <= 0)
	{
		printf("XS Error: to create socket\n");
		return -1;
	}

	if(sizeof(addr->sin_addr) == 0)
	{
		close(sd);
		printf("XS Error: invalid ip\n");
		return -1;
	}

	flags = fcntl(sd, F_GETFL, 0);
	if(fcntl( sd, F_SETFL, flags | O_NONBLOCK) == -1)
	{
		printf("XS Error: make nonblocking socket\n");
		close(sd);
		return -1;
	}

	connected = connect(sd, (struct sockaddr*)addr, sizeof(*addr));
	if (connected == -1 && errno != EINPROGRESS)
	{
		printf("XS Error: connect error (%s)\n", strerror(errno));
		close(sd);
		return -1;
	}

	{
		struct pollfd fds[1];
		int poll_ret;
		int timeout = 50000;

		fds[0].fd = sd;
		fds[0].events = POLLOUT;
		fds[0].revents = 0;

		poll_ret = poll(fds, 1, /* timeout in msec */ timeout);

		if(poll_ret == 0)
		{
			printf("Error server connect timeout [%s:%i, %i msec]\n",host, port, timeout);
			close(sd);
			return -1;
		}
		else if(poll_ret == -1 || poll_ret != 1)
		{
			printf("Error: poll error: %s [poll returns: %i]\n", strerror(errno), poll_ret);
			close(sd);
			return -1;
		}
	}

	flags = fcntl(sd, F_GETFL, 0);
	if(fcntl( sd, F_SETFL, flags & ~O_NONBLOCK) == -1)
	{
		printf("XS Error: make blocking socket\n");
		close(sd);
		return -1;
	}

	if(errno == EINPROGRESS)
		errno = 0;

	return sd;

}

static bool open_connect(xmemc_t *memc, char *host, int port, int64_t *total_timeout)
{
    struct hostent* hp = 0;
    //struct sockaddr_in addr;
    //int sd;
    int64_t mcs;
	struct timeval t_start;
	struct timeval t_end;

    if(init_alarm_handler(proc_sigalarm_simple) != 0)
    {
        printf("init_alarm_handler\n");
        return false;
    }

	set_timeout_once(1000);					// 1 millisec
	hp = gethostbyname(host);
	set_timeout_once(0);

    if(!hp)
    {
        printf("Error, !hp\n");
        return false;
    }

    memset(&memc->addr, 0, sizeof(memc->addr));
	memc->addr.sin_family = AF_INET;
	if(hp) memcpy(&memc->addr.sin_addr, hp->h_addr, hp->h_length);
	memc->addr.sin_port=htons(port);

	gettimeofday(&t_start, 0);
	memc->sd = timed_connect_remote_server((const struct sockaddr_in *)&memc->addr, host, port);
	gettimeofday(&t_end, 0);
	*total_timeout -= (t_end.tv_sec - t_start.tv_sec)*1000000 + (t_end.tv_usec - t_start.tv_usec);

	if(*total_timeout <= 0 && memc->sd >= 0)
	{
		printf("XS Error: server connect timeout [%s:%i, 50000 msec]",host, port);
		close(memc->sd);
		return false;;
	}

    printf("Succes, sd: %i\n", memc->sd);

	memc->rcv_buf = 0;
	memc->snd_buf = 0;

    if(memc->sd <= -1)
        return false;
	return true;

    //return sd;
}

int get_data(xmemc_t *memc, size_t *bytes_send, size_t *bytes_recv, int64_t *total_timeout, char *host)
{
    int bytes;
	struct timeval t_start;
	struct timeval t_end;
	int64_t mcs;
	struct timeval tv;

	if(memc->sd <= 0)
		return -1;
	
	if(!memc->snd_buf)
	{
		printf("XS Error: no send buffer for memcached\n");
		return -1;
	}

	gettimeofday(&t_start, 0);


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

    init_string(&realm);     init_string(&nonce);
    init_string(&stale);     init_string(&charset); 
    init_string(&algorithm); init_string(&auth_param_value);
    
    int res;
    int server_challenge_size = 0;
    //char host[] = "aqaa.bbb.ccc.imap.yandex.ru";
    char username[] = "sofia";
    char password[] = "123456";
    int client_maxbuf = 34676;

    *bytes_recv = 32267;
	memc->rcv_buf = (char *) malloc (*bytes_recv + 1);
	memset( memc->rcv_buf, 0, *bytes_recv );

	tv.tv_usec = *total_timeout;
	tv.tv_sec = 0;

	/*if(setsockopt(memc->sd, SOL_SOCKET, SO_RCVTIMEO,(char *)&tv,sizeof(tv)) != 0)
	{
		printf("XS Error: setsockopt failed for memcached server\n");
		return -1;
	}*/


    //Getting capability line from IMAP server
	bytes = recv(memc->sd, memc->rcv_buf, *bytes_recv, 0);
	if(bytes > 0) assert( bytes < *bytes_recv );
	else if (bytes == -1 && errno == 11) printf("Error while reading\n");
    printf("S: %s\n", memc->rcv_buf);
    if (!strcasestr(memc->rcv_buf, "OK"))
    {
        printf("Server sent bad answer, abort\n");
        return -1;
    }

    //sending request for authorization
    strcpy(memc->snd_buf, "1 AUTHENTICATE DIGEST-MD5\n");
    *bytes_send = strlen(memc->snd_buf);
    printf("C: %s\n", memc->snd_buf); 
    bytes = send(memc->sd, memc->snd_buf, *bytes_send, MSG_NOSIGNAL | MSG_DONTWAIT);
    //bytes = send(memc->sd, memc->snd_buf, *bytes_send, 0);
	if(bytes < 0)
	{
		printf("Error while sending: %i bytes(%s)\n", bytes, strerror(errno));
		return -1;
	}
    printf("bytes sent: %i\n", bytes);

    //waiting and recieving server's answer on our request
    memset( memc->rcv_buf, 0, *bytes_recv );
    bytes = recv(memc->sd, memc->rcv_buf, *bytes_recv, 0);
    if(bytes > 0) assert( bytes < *bytes_recv );
	else if (bytes == -1 && errno == 11) printf("Error while reading\n");
    printf("S: %s\n", memc->rcv_buf);

    
   //preparing response and sending it to server 
    char *tmp = memc->rcv_buf;
    if(*tmp == '+') tmp++;
    while(*tmp == ' ')tmp++;
    mpop_string request;
    init_string(&request);
    decoder_state state1;
    init_state(&state1);
    decode_base64(&request, tmp, &state1);
    decode_flush(&request, &state1);
    printf("request.string: %s\n", request.string);
    res = get_server_challenge_params(host, /*memc->rcv_buf*/ request.string, request.size, &realm,&nonce, &qop,
                                                 &stale, &maxbuf, &charset, &algorithm, &cipher, &auth_param,
                                                 &auth_param_value);

	//malloc_canary_check( memc->rcv_buf, bytes_recv );

    free_string(&request);

    char qop1[] = "auth";
    char cipher1[] = "";

    form_client_response_on_server_challenge(host, username, password, &response, &realm, &nonce, qop1, &stale, maxbuf, &charset, 
                                                    &algorithm, cipher1, &auth_param, &auth_param_value, client_maxbuf, nc);

    mpop_string req;
    init_string(&req);
    encoder_state state;
    init_encoder_state(&state);
    encode_base64(&req, response.string, response.size, &state);
    encode_flush(&req, &state);

    int n = req.size;
    for(int i = 0; i < n; i++)
    {
        if (req.string[i] == '\n')
        {
            int  j = i;
            for (; j < n - 1; j++)
                req.string[j]  = req.string[j+1];
            req.string[n - 1] = '\0';
            n--;
        }
    }

    printf("Base 64 response: %s\n", req.string);
    //strcpy(memc->snd_buf, "\n");
    sprintf(memc->snd_buf, "%s\n", req.string);
    *bytes_send = strlen(memc->snd_buf);
    printf("C: %s\n", memc->snd_buf);
    bytes = send(memc->sd, memc->snd_buf, *bytes_send, MSG_NOSIGNAL | MSG_DONTWAIT);
    if(bytes < 0)
    {
        printf("Error while sending: %i bytes(%s)\n", bytes, strerror(errno));
        return -1;
    }
    printf("bytes sent: %i\n", bytes);
    free_string(&req);

    //waiting and recieving server's answer on our request
    memset( memc->rcv_buf, 0, *bytes_recv );
    bytes = recv(memc->sd, memc->rcv_buf, *bytes_recv, 0);
    if(bytes > 0) assert( bytes < *bytes_recv );
    else if (bytes == -1 && errno == 11) printf("Error while reading\n");
    printf("S: %s\n", memc->rcv_buf);

   //gettintg rspath from server 
    tmp = memc->rcv_buf;
    if(*tmp == '+') tmp++;
    while(*tmp == ' ')tmp++;
    mpop_string request1;
    init_string(&request1);
    init_state(&state1);
    decode_base64(&request1, tmp, &state1);
    decode_flush(&request1, &state1);
    printf("decoded: %s\n", request1.string);

    if(strstr(request1.string, "rspauth") != NULL)
    {
        sprintf(memc->snd_buf, "\n");
        *bytes_send = strlen(memc->snd_buf);
        printf("C: %s\n", memc->snd_buf);
        bytes = send(memc->sd, memc->snd_buf, *bytes_send, MSG_NOSIGNAL | MSG_DONTWAIT);
        if(bytes < 0)
        {
             printf("Error while sending: %i bytes(%s)\n", bytes, strerror(errno));
             return -1;
        }

        memset( memc->rcv_buf, 0, *bytes_recv );
        bytes = recv(memc->sd, memc->rcv_buf, *bytes_recv, 0);
        if(bytes > 0) assert( bytes < *bytes_recv );
        else if (bytes == -1 && errno == 11) printf("Error while reading\n");
        printf("S: %s\n", memc->rcv_buf);
    }
    else 
    {
        printf("authentication failed\n");
    }
    
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


	gettimeofday(&t_end, 0);

	mcs = (t_end.tv_sec - t_start.tv_sec)*1000000;
	mcs += (t_end.tv_usec - t_start.tv_usec);
	printf("BLIMEM - %f sec\n", (double)mcs/1000000 );

	return bytes;
}


int main(int argc, char* argv[])
{
    /*if (argc != 3)
    {
        printf("Usage: chat_client <host> <port>\n");
        return 1;
    }*/

    char host[] = "localhost";
    int port = 143;
    int64_t total_timeout = 9999000;

    size_t bytes_send, bytes_recv;

    xmemc_t memc;

    if(!open_connect(&memc, host, port, &total_timeout))
    {
        printf("Someting has gone wrong\n");
        return -1;
    }
    if(total_timeout <= 0) return 0;


    bytes_recv = 0;
    memc.snd_buf = (char *) malloc (bytes_send + 1);

    if(!memc.snd_buf) return 0;

    get_data(&memc, &bytes_send, &bytes_recv, &total_timeout, host);

    //bytes_send
    close(memc.sd);
    return 1;
}
