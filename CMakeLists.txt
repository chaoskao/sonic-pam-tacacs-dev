PROJECT(tests)

CMAKE_MINIMUM_REQUIRED(VERSION 3.10)

set(PAM_TACPLUS_TEST_DIR ${CMAKE_SOURCE_DIR}/test/)
set(PAM_TACPLUS_DIR ${CMAKE_SOURCE_DIR}/pam_tacplus)

INCLUDE_DIRECTORIES(
    ${PAM_LIBTAC_INCLUDE_DIR}
    ${PAM_LIBTAC_SOURCE_DIR}
)

include(${CMAKE_ROOT}/Modules/ExternalProject.cmake)

ADD_EXECUTABLE(pam_tacplus_test
    ${PAM_TACPLUS_TEST_DIR}/pam_tacplus_test.cpp
)
TARGET_LINK_LIBRARIES(pam_tacplus_test
    gmock gtest gtest_main pthread ${PAM_TACPLUS_DIR}/pam_tacplus.a tac pam crypto
)
target_include_directories(pam_tacplus_test PRIVATE /home/nms/sonic-pam-tacacs-dev/client/include)

ADD_EXECUTABLE(pam_tacplus_socket_test
    ${PAM_TACPLUS_TEST_DIR}/pam_tacplus_socket_test.cpp
)
TARGET_LINK_LIBRARIES(pam_tacplus_socket_test
    gmock gtest gtest_main pthread ${PAM_TACPLUS_DIR}/pam_tacplus.a tac pam crypto
)

include(CTest)