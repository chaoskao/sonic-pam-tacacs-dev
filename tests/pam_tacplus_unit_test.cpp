#include <stdio.h>
#include "gmock/gmock.h"

extern "C"
{
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netdb.h>

    #include <security/pam_modules.h>
    #include <security/pam_appl.h>
    #include <security/pam_misc.h>

    #include "libtac/libtac.h"

    extern void authenticate(const struct addrinfo *tac_server, const char *tac_secret,
                const char *user, const char *pass, const char *tty,
                const char *remote_addr);
}

namespace PamTacPlusServerMockTest
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
        MOCK_METHOD3(getpeername, int(int sockfd, struct sockaddr *addr, socklen_t *addrlen));
        MOCK_METHOD3(bind, int(int sockfd, const struct sockaddr *addr, socklen_t addrlen));
        MOCK_METHOD5(select, int(int sockfd, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout));
        MOCK_METHOD3(connect, int(int sockfd, const struct sockaddr *addr, socklen_t addrlen));
        MOCK_METHOD3(write, ssize_t(int fd, const void *buf, size_t count));
        MOCK_METHOD3(read, ssize_t(int fd, void *buf, size_t count));
    };

    StrictMock<CoreLayer> *g_core_layer_p;

    class PamTacPlusServerMockTest : public Test
    {
    public:
        StrictMock<CoreLayer> core_layer_mock;

        PamTacPlusServerMockTest()
        {
            g_core_layer_p = &core_layer_mock;
        }

        ~PamTacPlusServerMockTest()
        {
        }

        void SetUp() override
        {
        }

        void TearDown() override
        {
        }
    };

    TEST_F(PamTacPlusServerMockTest, authenticate_Test)
    {
        const char *SERVER = "127.0.0.1";
        const char *KEY = "testing123";
        const char *user = "testguy";
        const char *pass = "abcd1234";
        const char *tty = "ppp";
        const char *remote_addr = "1.1.1.1";
        const int SERVER_TIMEOUT = 10;
        const int PKT_SIZE = 1024;
        int tac_fd;
        int ret;
        struct areply arep;
        struct addrinfo *tac_server;
        struct addrinfo hints;
        u_char req_pkt[PKT_SIZE];
        u_char resp_pkt[PKT_SIZE];
        size_t req_pkt_len = 0;
        size_t resp_pkt_len = 0;
        size_t resp_pkt_read_pos = 0;
        int is_resp_pkt_gen = 0;

        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        ret = getaddrinfo(SERVER, "tacacs", &hints, &tac_server);
        ASSERT_EQ(0, ret);

        auto WriteReqPktFunc = [PKT_SIZE, &req_pkt, &req_pkt_len](const void *buf, size_t count)
        {
            ASSERT_TRUE(PKT_SIZE >= count + req_pkt_len);

            memcpy(&req_pkt[req_pkt_len], buf, count);
            req_pkt_len += count;
        };

        auto ReadRespPktFunc = [PKT_SIZE, &tac_fd, &req_pkt, &req_pkt_len, &resp_pkt, &resp_pkt_len, &resp_pkt_read_pos, &is_resp_pkt_gen](int fd, void *buf, size_t count) -> ssize_t
        {
            size_t read_len = 0;

            if (tac_fd != fd)
            {
                return 0;
            }

            if (0 == is_resp_pkt_gen)
            {
                HDR *req_header_p = (HDR *)&req_pkt;
                HDR *resp_header_p = (HDR *)&resp_pkt;
                authen_reply *resp_pkt_data_p;

                // ASSERT_EQ(ntohl(req_header_p->datalength) + sizeof(*req_header_p), req_pkt_len);

                /* header
                 */
                resp_header_p->version = req_header_p->version;
                resp_header_p->type = req_header_p->type;
                resp_header_p->seq_no = req_header_p->seq_no + 1;
                resp_header_p->session_id = req_header_p->session_id;
                resp_header_p->datalength = htonl(sizeof(*resp_pkt_data_p));
                resp_header_p->encryption = TAC_PLUS_ENCRYPTED_FLAG;

                /* data body
                 */
                resp_pkt_data_p = (authen_reply *)((u_char *)resp_pkt + sizeof(*resp_header_p));
                memset(resp_pkt_data_p, 0, sizeof(*resp_pkt_data_p));
                resp_pkt_data_p->status = TAC_PLUS_AUTHEN_STATUS_PASS;

                _tac_crypt((u_char *)resp_pkt_data_p, resp_header_p, sizeof(*resp_header_p));

                is_resp_pkt_gen = 1;
                resp_pkt_len = sizeof(*resp_header_p) + sizeof(*resp_pkt_data_p);
            }

            if (resp_pkt_read_pos < resp_pkt_len)
            {
                read_len = ((resp_pkt_len - resp_pkt_read_pos) < count) ? (resp_pkt_len - resp_pkt_read_pos) : count;
                memcpy(buf, &resp_pkt[resp_pkt_read_pos], read_len);
                resp_pkt_read_pos += read_len;
            }

            return read_len;
        };

        EXPECT_CALL(core_layer_mock, getpeername(_, _, _))
            .WillRepeatedly(Return(0));
        EXPECT_CALL(core_layer_mock, bind(_, _, _))
            .WillRepeatedly(Return(0));
        EXPECT_CALL(core_layer_mock, connect(_, _, _))
            .WillRepeatedly(Return(0));
        EXPECT_CALL(core_layer_mock, select(_, _, _,_,_))
            .WillRepeatedly(Return(1));
        EXPECT_CALL(core_layer_mock, write(_, _, _))
            .WillRepeatedly(
                DoAll(
                    WithArgs<1,2>(Invoke(WriteReqPktFunc)),
                    ReturnArg<2>()
                    )
                );
        EXPECT_CALL(core_layer_mock, read(_, _, _))
            .WillRepeatedly(Invoke(ReadRespPktFunc));

        tac_fd = tac_connect_single(tac_server, KEY, NULL, 60);
        ASSERT_TRUE(0 < tac_fd);

        /* start authentication */

        ret = tac_authen_send(tac_fd, user, pass, tty, remote_addr, TAC_PLUS_AUTHEN_LOGIN);
        ASSERT_EQ(0, ret);

        ret = tac_authen_read(tac_fd, &arep);
        ASSERT_EQ(TAC_PLUS_AUTHEN_STATUS_PASS, ret);
    }
}

extern "C"
{
    int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
    {
        return PamTacPlusServerMockTest::g_core_layer_p->getpeername(sockfd, addr, addrlen);
    }

    int bind(int sockfd, const struct sockaddr *addr,
                    socklen_t addrlen)
    {
        return PamTacPlusServerMockTest::g_core_layer_p->bind(sockfd, addr, addrlen);
    }
    int select(int sockfd, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
    {
        return PamTacPlusServerMockTest::g_core_layer_p->select(sockfd, readfds, writefds, exceptfds, timeout);
    }

    int connect(int sockfd, const struct sockaddr *addr,
                   socklen_t addrlen)
    {
        return PamTacPlusServerMockTest::g_core_layer_p->connect(sockfd, addr, addrlen);
    }

    ssize_t write(int fd, const void *buf, size_t count)
    {
        return PamTacPlusServerMockTest::g_core_layer_p->write(fd, buf, count);
    }

    ssize_t read(int fd, void *buf, size_t count)
    {
        return PamTacPlusServerMockTest::g_core_layer_p->read(fd, buf, count);
    }
}
