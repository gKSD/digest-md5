#include <string>
#include <sstream>
#include <iostream>

#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory>
#include <string.h>
#include <fcntl.h>

#define MAXBUF      1024


/*
 *  To create collector from local server, need update rpop.imap like:
 *  update rpop.imap set flags=662, password='imaptest', encpassword='', autoconfigure='no', host='localhost', port=7788 where id=2668;
 *
 *  then need starting this simple server like:
 *  ./simple_test_server 7788
 */


int s2i(const char* s)
{
    std::stringstream ss;
    ss << s;
    int i;
    ss >> i;
    return i;
}

void test_send(int fd, const std::string &s)
{
    std::cerr << "send: " << s << "\n";
    send(fd, s.c_str(), s.size() , 0);
}

void test_recv(int fd, std::string &line)
{
    char buffer[MAXBUF];
    memset(buffer, 0, MAXBUF);
    recv(fd, buffer, MAXBUF, 0);
    line.assign(buffer);
    std::cerr << "recv: " << line << "\n";
}


int main(int argc, char *argv[])
{
    int port;
    if(argc < 2)
    {
        std::cerr << "need port\n";
        return -1;
    }
    else
    {
        port = s2i(argv[1]);
        std::cerr << "server started at: port="<< port << "\n";
    }

    int sockfd;
    struct sockaddr_in self;

    if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
    {
        perror("Socket");
        exit(errno);
    }

    fcntl(sockfd, F_SETFD, FD_CLOEXEC);

    memset(&self, 0, sizeof(self));
    self.sin_family = AF_INET;
    self.sin_port = htons(port);
    self.sin_addr.s_addr = INADDR_ANY;

    if ( bind(sockfd, (struct sockaddr*)&self, sizeof(self)) != 0 )
    {
        perror("socket--bind");
        exit(errno);
    }

    if ( listen(sockfd, 20) != 0 )
    {
        perror("socket--listen");
        exit(errno);
    }

    while (1)
    {
        std::string line;
        int fd;
        struct sockaddr_in client_addr;
        int addrlen=sizeof(client_addr);

        fd = accept(sockfd, (struct sockaddr*)&client_addr, (socklen_t*)&addrlen);
        printf("%s:%d connected\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));


        test_send(fd, "HELLO FROM TEST SERVER!!!\r\n");

        test_recv(fd, line);

        //if(line.find("LOGIN") != std::string::npos)
        if(0)
        {
            test_send(fd, "* HUI TEBE A NE LOGIN !!!\r\n");
            close(sockfd);
            close(fd);
            return 0;
        }
        else
            test_send(fd, "1 OK Login\r\n");

        test_recv(fd, line);
        if(line.find("CAPABILITY") != std::string::npos)
             test_send(fd, "2 OK CAPABILITY test XXX !!!\r\n");

        test_recv(fd, line);
        if(line.find("LIST") != std::string::npos)
        {
             test_send(fd, "* list (\\Unmarked \\NoInferiors) \"|\" INBOX\r\n");
             test_send(fd, "3 OK list\r\n");
        }

        test_recv(fd, line);
        if(line.find("STATUS") != std::string::npos)
        {
             test_send(fd, "* STATUS INBOX (UIDNEXT 241 MESSAGES 1 UIDVALIDITY 1376944396\r\n");
             test_send(fd, "4 OK status completed\r\n");
        }

        test_recv(fd, line);
        if(line.find("SELECT") != std::string::npos)
        {
             test_send(fd, "5 OK [READ-WRITE] select completed\r\n");
        }

        test_recv(fd, line);
        if(line.find("UID FETCH") != std::string::npos)
        {
             test_send(fd, "* 1 FETCH (UID 500 FLAGS (\\Seen) INTERNALDATE \"21-Feb-2014 11:16:33 +0000\")\r\n");
             //test_send(fd, "* 2 FETCH (UID 501 FLAGS (\\Seen) INTERNALDATE \"21-Feb-2014 11:16:33 +0000\")\r\n");
             test_send(fd, "6 OK uid fetch completed\r\n");
        }

        test_recv(fd, line);
        if(line.find("BODY.PEEK") != std::string::npos)
        {
             //test_send(fd, "* 413 FETCH (UID 907 BODY[] NIL)\r\n");
             test_send(fd, "* 16 FETCH (BODY[] \"\" UID 16)\r\n");
             test_send(fd, "7 OK [CLIENTBUG] uid fetch completed (no messages)\r\n");
        }

        test_recv(fd, line);
        if(line.find("LOGOUT") != std::string::npos)
        {
             test_send(fd, "8 OK By test server!!!\r\n");
        }

         test_send(fd, "GOOD BY\r\n");
         close(fd);
    }

    close(sockfd);
    return 0;
}
