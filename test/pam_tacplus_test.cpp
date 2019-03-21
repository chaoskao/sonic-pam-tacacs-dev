#include <stdio.h>
#include "gmock/gmock.h"

extern "C"
{
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netdb.h>

    #include <security/pam_modules.h>

    #include "libtac/libtac.h"

    extern void authenticate(const struct addrinfo *tac_server, const char *tac_secret,
                const char *user, const char *pass, const char *tty,
                const char *remote_addr);
}

namespace PamTacPlusTest
{
    using namespace std;
    using namespace std::tr1;
    using namespace testing;
    using ::testing::_;

    class Tool
    {
        public:
    };

    class CoreLayer
    {
    public:
    };

    StrictMock<CoreLayer> *g_core_layer_p;

    class PamTacPlusTest : public Test
    {
    public:
        StrictMock<CoreLayer> core_layer_mock;

        PamTacPlusTest()
        {
            g_core_layer_p = &core_layer_mock;
        }

        ~PamTacPlusTest()
        {
        }

        void SetUp()
        {
        }

        void TearDown()
        {
        }
    };

    TEST_F(PamTacPlusTest, pam_sm_authenticate_Test)
    {
        pam_sm_authenticate(NULL, 0, 0, NULL);
    }

    TEST_F(PamTacPlusTest, authenticate_Test)
    {
        const char *SERVER = "192.168.137.70";
        const char *KEY = "accton";
        const int SERVER_TIMEOUT = 10;
        int tac_fd;
        int ret;
        struct addrinfo *tac_server;
        struct addrinfo hints;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        ret = getaddrinfo(SERVER, "tacacs", &hints, &tac_server);
        ASSERT_EQ(0, ret);

        authenticate(tac_server, KEY, "kevin", "hello", "tty", "192.168.137.160");
    }

    TEST_F(PamTacPlusTest, tac_connect_single_Test)
    {

    }
}

extern "C"
{
    /* from tacc.c in pam_tacplus project
     */
#define    EXIT_OK        0
#define    EXIT_FAIL    1    /* AAA failure (or server error) */
#define    EXIT_ERR    2    /* local error */

int quiet = 0;

void authenticate(const struct addrinfo *tac_server, const char *tac_secret,
                  const char *user, const char *pass, const char *tty,
                  const char *remote_addr) {
    int tac_fd;
    int ret;
    struct areply arep;

    tac_fd = tac_connect_single(tac_server, tac_secret, NULL, 60);
    if (tac_fd < 0) {
        if (!quiet)
            printf("Error connecting to TACACS+ server: %m\n");
        exit(EXIT_ERR);
    }

    /* start authentication */

    if (tac_authen_send(tac_fd, user, pass, tty, remote_addr,
                        TAC_PLUS_AUTHEN_LOGIN) < 0) {
        if (!quiet)
            printf("Error sending query to TACACS+ server\n");
        exit(EXIT_ERR);
    }

    ret = tac_authen_read(tac_fd, &arep);

    if (ret == TAC_PLUS_AUTHEN_STATUS_GETPASS) {

        if (tac_cont_send(tac_fd, pass) < 0) {
            if (!quiet)
                printf("Error sending query to TACACS+ server\n");
            exit(EXIT_ERR);
        }

        ret = tac_authen_read(tac_fd, &arep);
    }

    if (ret != TAC_PLUS_AUTHEN_STATUS_PASS) {
        if (!quiet)
            printf("Authentication FAILED: %s\n", arep.msg);
        syslog(LOG_ERR, "authentication failed for %s: %s", user, arep.msg);
        exit(EXIT_FAIL);
    }

    if (!quiet)
        printf("Authentication OK\n");
    syslog(LOG_INFO, "authentication OK for %s", user);

    close(tac_fd);
}
}
