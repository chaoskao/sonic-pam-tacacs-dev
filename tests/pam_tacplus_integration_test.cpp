#include <stdio.h>
#include "gmock/gmock.h"
#include <unistd.h>
#include "config.h"
#include <iostream>
#include <sstream>

extern "C"
{
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netdb.h>

    #include <security/pam_modules.h>

    #include "libtac/libtac.h"   
}

namespace PamTacPlusTest
{
    using namespace std;
    using namespace testing;

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

        void SetUp() override
        {
            std::stringstream path;
            path << SERVER_BIN_PATH << "/tac_plus -C " << SERVER_BIN_PATH << "/tac_plus.conf -p " << SERVER_PORT;
            
            system(path.str().c_str());
            sleep(5);
        }

        void TearDown() override
        {
            system("killall tac_plus");   
        }
    };

    TEST_F(PamTacPlusTest, authenticate_Test)
    {
        const char *SERVER = "127.0.0.1";
        const char *KEY = "testing123";
		const char *user = "testguy";
        const char *pass = "abcd1234";
        const char *tty = "ppp";
        const char *remote_addr = "1.1.1.1";
        const int SERVER_TIMEOUT = 10;
        int tac_fd;
        int ret;
        struct areply arep;
        struct addrinfo *tac_server;
        struct addrinfo hints;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        

        ret = getaddrinfo(SERVER, SERVER_PORT, &hints, &tac_server);
        ASSERT_EQ(0, ret);

        tac_fd = tac_connect_single(tac_server, KEY, NULL, 60);
        ASSERT_TRUE(0 < tac_fd);

        /* start authentication */

        ret = tac_authen_send(tac_fd, user, pass, tty, remote_addr, TAC_PLUS_AUTHEN_LOGIN);
        ASSERT_EQ(0, ret);

        ret = tac_authen_read(tac_fd, &arep);
        ASSERT_EQ(TAC_PLUS_AUTHEN_STATUS_PASS, ret);

        close(tac_fd);
    }
}
