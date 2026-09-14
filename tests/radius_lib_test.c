#include "test_support.h"

static int
test_access_request_message_authenticator(void)
{
    uint8_t packet[RADIUS_PKG_MAX];
    uint8_t req_auth[AUTH_BUF_SIZE];
    uint8_t expected[AUTH_BUF_SIZE];
    uint8_t verification[RADIUS_PKG_MAX];
    ngx_str_t user = STR("alice");
    ngx_str_t password = STR("password");
    ngx_str_t secret = STR("testing123");
    ngx_str_t nas_id = STR("nginx");

    srandom(1);
    size_t len = create_radius_pkg(packet, sizeof(packet), 7,
                                   &user, &password, &secret, &nas_id,
                                   req_auth);
    CHECK(len > RADIUS_HEADER_SIZE);
    CHECK(packet[0] == 1);
    CHECK(packet[1] == 7);
    CHECK(((size_t) packet[2] << 8 | packet[3]) == len);
    CHECK(memcmp(packet + 4, req_auth, AUTH_BUF_SIZE) == 0);

    uint8_t *message_auth = find_message_authenticator(packet, len);
    CHECK(message_auth != NULL);
    CHECK(count_message_authenticators(packet, len) == 1);

    memcpy(verification, packet, len);
    message_auth = find_message_authenticator(verification, len);
    memset(message_auth, 0, AUTH_BUF_SIZE);
    independent_hmac(expected, verification, len, &secret);
    CHECK(memcmp(packet + (message_auth - verification),
                 expected, AUTH_BUF_SIZE) == 0);

    return 0;
}

static int
test_long_hmac_key(void)
{
    uint8_t packet[RADIUS_PKG_MAX];
    uint8_t verification[RADIUS_PKG_MAX];
    uint8_t expected[AUTH_BUF_SIZE];
    uint8_t secret_data[80];
    ngx_str_t user = STR("alice");
    ngx_str_t password = STR("password");
    ngx_str_t nas_id = STR("nginx");
    ngx_str_t secret = { sizeof(secret_data), secret_data };

    memset(secret_data, 's', sizeof(secret_data));
    size_t len = create_radius_pkg(packet, sizeof(packet), 9,
                                   &user, &password, &secret, &nas_id, NULL);
    CHECK(len > 0);

    memcpy(verification, packet, len);
    uint8_t *message_auth = find_message_authenticator(verification, len);
    CHECK(message_auth != NULL);
    memset(message_auth, 0, AUTH_BUF_SIZE);
    independent_hmac(expected, verification, len, &secret);
    CHECK(memcmp(packet + (message_auth - verification),
                 expected, AUTH_BUF_SIZE) == 0);

    return 0;
}

static int
test_attribute_errors_propagate(void)
{
    uint8_t packet[RADIUS_PKG_MAX];
    uint8_t user_data[64];
    uint8_t password_data[129];
    uint8_t max_password_data[128];
    uint8_t accepted_password_data[127];
    uint8_t nas_data[65];
    ngx_str_t empty = STR("");
    ngx_str_t secret = STR("testing123");
    ngx_str_t nas_id = STR("nginx");
    ngx_str_t long_user = { sizeof(user_data), user_data };
    ngx_str_t long_password = { sizeof(password_data), password_data };
    ngx_str_t max_password = { sizeof(max_password_data), max_password_data };
    ngx_str_t accepted_password = {
        sizeof(accepted_password_data), accepted_password_data
    };
    ngx_str_t long_nas = { sizeof(nas_data), nas_data };

    memset(user_data, 'u', sizeof(user_data));
    memset(password_data, 'p', sizeof(password_data));
    memset(max_password_data, 'p', sizeof(max_password_data));
    memset(accepted_password_data, 'p', sizeof(accepted_password_data));
    memset(nas_data, 'n', sizeof(nas_data));

    CHECK(create_radius_pkg(packet, sizeof(packet), 1,
                            &long_user, &empty, &secret, &nas_id, NULL) == 0);
    CHECK(create_radius_pkg(packet, sizeof(packet), 1,
                            &empty, &long_password, &secret, &nas_id, NULL) == 0);
    CHECK(create_radius_pkg(packet, sizeof(packet), 1,
                            &empty, &max_password, &secret, &nas_id, NULL) == 0);
    CHECK(create_radius_pkg(packet, sizeof(packet), 1,
                            &empty, &accepted_password, &secret,
                            &nas_id, NULL) > 0);
    CHECK(create_radius_pkg(packet, sizeof(packet), 1,
                            &empty, &empty, &secret, &long_nas, NULL) == 0);

    return 0;
}

static int
test_golden_response(void)
{
    ngx_str_t secret = STR("testing123");

    CHECK(parse_radius_pkg(golden_response, sizeof(golden_response), 7,
                           request_authenticator, &secret) ==
          RADIUS_AUTH_ACCEPTED);
    return 0;
}

static int
test_response_authenticator_errors(void)
{
    uint8_t packet[sizeof(golden_response)];
    ngx_str_t secret = STR("testing123");

    memcpy(packet, golden_response, sizeof(packet));
    packet[4] ^= 1;
    CHECK(parse_radius_pkg(packet, sizeof(packet), 7,
                           request_authenticator, &secret) ==
          RADIUS_PARSE_ERR_RESPONSE_AUTH);

    memcpy(packet, golden_response, sizeof(packet));
    uint8_t *message_auth = find_message_authenticator(packet, sizeof(packet));
    CHECK(message_auth != NULL);
    message_auth[0] ^= 1;
    set_response_authenticator(packet, sizeof(packet),
                               request_authenticator, &secret);
    CHECK(parse_radius_pkg(packet, sizeof(packet), 7,
                           request_authenticator, &secret) ==
          RADIUS_PARSE_ERR_MESSAGE_AUTH);

    return 0;
}

static int
test_legacy_response_without_message_authenticator(void)
{
    uint8_t packet[RADIUS_HEADER_SIZE] = {
        0x02, 0x07, 0x00, RADIUS_HEADER_SIZE,
    };
    ngx_str_t secret = STR("testing123");

    set_response_authenticator(packet, sizeof(packet),
                               request_authenticator, &secret);
    CHECK(parse_radius_pkg(packet, sizeof(packet), 7,
                           request_authenticator, &secret) ==
          RADIUS_AUTH_ACCEPTED);
    return 0;
}

static int
test_reject_with_attributes_around_message_authenticator(void)
{
    uint8_t packet[46] = {
        0x03, 0x07, 0x00, sizeof(packet),
    };
    ngx_str_t secret = STR("testing123");

    packet[20] = 1;
    packet[21] = 5;
    memcpy(packet + 22, "bob", 3);
    packet[25] = MESSAGE_AUTHENTICATOR_TYPE;
    packet[26] = MESSAGE_AUTHENTICATOR_SIZE;
    packet[43] = 18;
    packet[44] = 3;
    packet[45] = 'x';

    set_message_authenticator(packet, sizeof(packet),
                              request_authenticator, &secret);
    set_response_authenticator(packet, sizeof(packet),
                               request_authenticator, &secret);

    CHECK(parse_radius_pkg(packet, sizeof(packet), 7,
                           request_authenticator, &secret) ==
          RADIUS_AUTH_REJECTED);
    return 0;
}

static int
test_malformed_attributes(void)
{
    uint8_t packet[64];
    ngx_str_t secret = STR("testing123");

    memcpy(packet, golden_response, sizeof(golden_response));
    packet[21] = 17;
    CHECK(parse_radius_pkg(packet, sizeof(golden_response), 7,
                           request_authenticator, &secret) ==
          RADIUS_PARSE_ERR_ATTRIBUTE);

    memset(packet, 0, 56);
    packet[0] = 2;
    packet[1] = 7;
    packet[2] = 0;
    packet[3] = 56;
    packet[20] = MESSAGE_AUTHENTICATOR_TYPE;
    packet[21] = MESSAGE_AUTHENTICATOR_SIZE;
    packet[38] = MESSAGE_AUTHENTICATOR_TYPE;
    packet[39] = MESSAGE_AUTHENTICATOR_SIZE;
    CHECK(parse_radius_pkg(packet, 56, 7, request_authenticator, &secret) ==
          RADIUS_PARSE_ERR_ATTRIBUTE);

    memset(packet, 0, 23);
    packet[0] = 2;
    packet[1] = 7;
    packet[2] = 0;
    packet[3] = 23;
    packet[20] = 1;
    packet[21] = 4;
    CHECK(parse_radius_pkg(packet, 23, 7, request_authenticator, &secret) ==
          RADIUS_PARSE_ERR_ATTRIBUTE);

    return 0;
}

static int
test_packet_length_handling(void)
{
    uint8_t packet[sizeof(golden_response) + 1];
    ngx_str_t secret = STR("testing123");

    CHECK(parse_radius_pkg(golden_response, RADIUS_HEADER_SIZE - 1, 7,
                           request_authenticator, &secret) ==
          RADIUS_PARSE_ERR_LENGTH);

    memcpy(packet, golden_response, sizeof(golden_response));
    packet[sizeof(golden_response)] = 0xaa;
    CHECK(parse_radius_pkg(packet, sizeof(packet), 7,
                           request_authenticator, &secret) ==
          RADIUS_PARSE_ERR_LENGTH);

    memcpy(packet, golden_response, sizeof(golden_response));
    packet[3] = sizeof(packet);
    CHECK(parse_radius_pkg(packet, sizeof(golden_response), 7,
                           request_authenticator, &secret) ==
          RADIUS_PARSE_ERR_LENGTH);

    CHECK(parse_radius_pkg(golden_response, sizeof(golden_response), 8,
                           request_authenticator, &secret) ==
          RADIUS_PARSE_ERR_ID);

    return 0;
}

int
main(void)
{
    CHECK(test_access_request_message_authenticator() == 0);
    CHECK(test_long_hmac_key() == 0);
    CHECK(test_attribute_errors_propagate() == 0);
    CHECK(test_golden_response() == 0);
    CHECK(test_response_authenticator_errors() == 0);
    CHECK(test_legacy_response_without_message_authenticator() == 0);
    CHECK(test_reject_with_attributes_around_message_authenticator() == 0);
    CHECK(test_malformed_attributes() == 0);
    CHECK(test_packet_length_handling() == 0);

    puts("radius_lib tests: passed");
    return 0;
}
