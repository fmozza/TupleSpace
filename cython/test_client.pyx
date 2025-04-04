# test_client.pyx
from libc.stdlib cimport malloc, free
from libc.string cimport memcpy, memset
from libc.stdint cimport uint8_t, uint32_t, uint64_t, int64_t
from posix.unistd cimport close
from libc.stddef cimport size_t

cdef extern from "sys/socket.h":
    int socket(int domain, int type, int protocol)
    int connect(int sockfd, const void *addr, size_t addrlen)
    ssize_t send(int sockfd, const void *buf, size_t len, int flags)
    ssize_t recv(int sockfd, void *buf, size_t len, int flags)
    int AF_INET
    int SOCK_STREAM

cdef extern from "arpa/inet.h":
    uint32_t htonl(uint32_t hostlong)
    uint32_t ntohl(uint32_t netlong)

cdef extern from "stdio.h":
    ctypedef struct FILE:
        pass
    FILE *stdout
    FILE *fopen(const char *path, const char *mode)
    int fclose(FILE *fp)

cdef extern from "openssl/evp.h":
    ctypedef struct EVP_PKEY:
        pass
    ctypedef struct EVP_PKEY_CTX:
        pass
    ctypedef struct EVP_MD_CTX:
        pass
    ctypedef struct EVP_MD:
        pass
    int EVP_PKEY_X25519
    EVP_PKEY *EVP_PKEY_new_raw_public_key(int type, void *unused, const unsigned char *key, size_t len)
    int EVP_PKEY_get_raw_public_key(EVP_PKEY *pkey, unsigned char *pub, size_t *len)
    void EVP_PKEY_free(EVP_PKEY *pkey)
    EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, void *engine)
    int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx)
    int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer)
    int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
    void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx)
    EVP_MD_CTX *EVP_MD_CTX_new()
    int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, void *impl)
    int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
    int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s)
    void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
    const EVP_MD *EVP_sha256()

cdef extern from "openssl/pem.h":
    EVP_PKEY *PEM_read_PrivateKey(FILE *fp, EVP_PKEY **x, void *cb, void *u)

cdef extern from "tuple_encrypt.h":
    void encrypt_generate_nonce(unsigned char *nonce, size_t len)
    int encrypt_encrypt_message(const unsigned char *session_key, const unsigned char *nonce,
                                const uint8_t *plaintext, size_t plaintext_len,
                                uint8_t **ciphertext, size_t *ciphertext_len)
    int encrypt_decrypt_message(const unsigned char *session_key, const unsigned char *nonce,
                                const unsigned char *ciphertext, size_t ciphertext_len,
                                uint8_t **plaintext, size_t *plaintext_len)

cdef extern from "tuple_network_client.c":
    int network_connect_client(const char *host, int port, int *clientfd)

cdef extern from "tuple.h":
    ctypedef enum ElementTag:
        ELEMENT_INT = 0
        ELEMENT_FLOAT
        ELEMENT_STRING
        ELEMENT_TUPLE
        ELEMENT_INT_ARRAY
        ELEMENT_FLOAT_ARRAY
        ELEMENT_WILDCARD
    ctypedef enum TupleState:
        STATE_NEW = 0
        STATE_TAKEN
        STATE_DONE
        STATE_RET
    ctypedef struct String:
        const char *ptr
        size_t len
    ctypedef struct IntArray:
        const int64_t *ptr
        size_t len
    ctypedef struct FloatArray:
        const double *ptr
        size_t len
    ctypedef struct Tuple:
        pass  # Forward declaration
    ctypedef union ElementData:
        int64_t Int
        double Float
        String String
        Tuple *Tuple
        IntArray IntArray
        FloatArray FloatArray
    ctypedef struct Element:
        ElementTag tag
        ElementData data
    ctypedef struct Tuple:
        uint64_t id
        char space_id[32]
        char label[32]
        Element *elements
        size_t elements_len
        uint64_t client_id
        uint64_t resource_id
        uint64_t request_id
        int64_t timestamp
        TupleState state
    uint64_t generate_tuple_id()
    Tuple *tuple_init(size_t elements_len)
    void tuple_set_element(Tuple *self, size_t index, ElementTag tag, ElementData data)
    void tuple_deinit(Tuple *self)
    int tuple_serialize(Tuple *self, uint8_t **buffer, size_t *len)
    Tuple *tuple_deserialize(uint8_t **buffer, size_t len)

cdef extern from "tuple_utils.h":
    Tuple *create_test_tuple()

cdef class TestClient:
    cdef int clientfd
    cdef unsigned char session_key[32]
    cdef EVP_PKEY *client_key

    def __cinit__(self, host: str = "reimann", port: int = 42420):
        cdef bytes b_host = host.encode('utf-8')
        cdef FILE *fp
        cdef char *key_path = "/usr/local/tuple_space/.keys/client_01_key.pem"
        cdef unsigned char client_pub_key[32]
        cdef size_t client_pub_len = 32
        cdef unsigned char server_pub_key[32]
        cdef EVP_PKEY *server_key
        cdef EVP_PKEY_CTX *ctx
        cdef size_t secret_len = 32
        cdef unsigned char shared_secret[32]

        if network_connect_client(b_host, port, &self.clientfd) != 0:
            raise RuntimeError("Failed to connect to server")

        fp = fopen(key_path, "r")
        if fp == NULL:
            raise RuntimeError("Failed to open client key file")
        self.client_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL)
        fclose(fp)
        if self.client_key == NULL:
            raise RuntimeError("Failed to load client key")

        if EVP_PKEY_get_raw_public_key(self.client_key, client_pub_key, &client_pub_len) != 1:
            raise RuntimeError("Failed to extract client public key")
        print(f"Client pubkey: {client_pub_key[:4].hex()}...")
        if send(self.clientfd, client_pub_key, 32, 0) != 32:
            raise RuntimeError("Failed to send client public key")

        cdef ssize_t recvd = recv(self.clientfd, server_pub_key, 32, 0)
        if recvd != 32:
            raise RuntimeError(f"Failed to receive server public key: got {recvd} bytes")
        print(f"Server pubkey: {server_pub_key[:4].hex()}...")

        server_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, server_pub_key, 32)
        if server_key == NULL:
            raise RuntimeError("Failed to create server key")

        ctx = EVP_PKEY_CTX_new(self.client_key, NULL)
        if EVP_PKEY_derive_init(ctx) <= 0 or EVP_PKEY_derive_set_peer(ctx, server_key) <= 0:
            EVP_PKEY_free(server_key)
            EVP_PKEY_CTX_free(ctx)
            raise RuntimeError("Failed to init key derivation")
        if EVP_PKEY_derive(ctx, shared_secret, &secret_len) <= 0:
            EVP_PKEY_free(server_key)
            EVP_PKEY_CTX_free(ctx)
            raise RuntimeError("Failed to derive shared secret")
        EVP_PKEY_CTX_free(ctx)

        cdef EVP_MD_CTX *md_ctx = EVP_MD_CTX_new()
        if md_ctx == NULL or EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1:
            EVP_MD_CTX_free(md_ctx)
            EVP_PKEY_free(server_key)
            raise RuntimeError("Failed to init SHA-256")
        if EVP_DigestUpdate(md_ctx, shared_secret, secret_len) != 1:
            EVP_MD_CTX_free(md_ctx)
            EVP_PKEY_free(server_key)
            raise RuntimeError("Failed to update SHA-256")
        cdef unsigned int digest_len
        if EVP_DigestFinal_ex(md_ctx, self.session_key, &digest_len) != 1 or digest_len != 32:
            EVP_MD_CTX_free(md_ctx)
            EVP_PKEY_free(server_key)
            raise RuntimeError("Failed to finalize SHA-256")
        EVP_MD_CTX_free(md_ctx)
        EVP_PKEY_free(server_key)
        print(f"Session key: {self.session_key[:4].hex()}...")

    def __dealloc__(self):
        if self.clientfd >= 0:
            close(self.clientfd)
        if self.client_key != NULL:
            EVP_PKEY_free(self.client_key)

    def send_test_message(self):
        cdef unsigned char nonce[12]
        cdef unsigned char *ciphertext = NULL
        cdef size_t ciphertext_len
        cdef uint8_t *serialized = NULL
        cdef size_t serialized_len
        cdef uint32_t msg_len
        cdef unsigned char space_id[32]
        cdef unsigned char *msg_buffer

        cdef Tuple *t = create_test_tuple()
        if t == NULL:
            raise MemoryError("Failed to init tuple")

        if tuple_serialize(t, &serialized, &serialized_len) != 0:
            tuple_deinit(t)
            raise RuntimeError("Failed to serialize tuple")

        cdef size_t plaintext_len = 1 + serialized_len
        cdef uint8_t *plaintext = <uint8_t *>malloc(plaintext_len)
        if plaintext == NULL:
            free(serialized)
            tuple_deinit(t)
            raise MemoryError("Failed to allocate plaintext")
        plaintext[0] = 0  # OP_PUT
        memcpy(plaintext + 1, serialized, serialized_len)
        free(serialized)
        tuple_deinit(t)

        encrypt_generate_nonce(nonce, 12)
        print(f"Nonce: {nonce[:4].hex()}...")

        if encrypt_encrypt_message(self.session_key, nonce, plaintext, plaintext_len,
                                   &ciphertext, &ciphertext_len) != 0:
            free(plaintext)
            raise RuntimeError("Failed to encrypt message")
        print(f"Ciphertext len: {ciphertext_len - 16}, Tag: {ciphertext[ciphertext_len - 16:ciphertext_len][:4].hex()}...")
        free(plaintext)

        cdef size_t total_len = 12 + 32 + ciphertext_len
        msg_len = htonl(total_len)
        msg_buffer = <unsigned char *>malloc(total_len + 4)
        if msg_buffer == NULL:
            free(ciphertext)
            raise MemoryError("Failed to allocate message buffer")

        memcpy(msg_buffer, &msg_len, 4)
        memcpy(msg_buffer + 4, nonce, 12)
        memset(space_id, 0, 32)
        memcpy(msg_buffer + 4 + 12, space_id, 32)
        memcpy(msg_buffer + 4 + 12 + 32, ciphertext, ciphertext_len)
        
        print(f"Sending {total_len + 4} bytes: {msg_buffer[:total_len + 4].hex()}...")
        free(ciphertext)

        cdef ssize_t sent = send(self.clientfd, msg_buffer, total_len + 4, 0)
        if sent != <ssize_t>(total_len + 4):
            free(msg_buffer)
            raise RuntimeError(f"Failed to send message: sent {sent}, expected {total_len + 4}")
        print(f"Sent {sent} bytes")

        cdef unsigned char response[1024]
        cdef ssize_t recvd = recv(self.clientfd, response, sizeof(response), 0)
        if recvd <= 0:
            free(msg_buffer)
            raise RuntimeError(f"Failed to receive response: {recvd} bytes")
        print(f"Received {recvd} bytes")

        cdef uint32_t resp_len = ntohl((<uint32_t *>response)[0])
        cdef unsigned char *resp_plaintext = NULL
        cdef size_t resp_plaintext_len
        if encrypt_decrypt_message(self.session_key, response + 4, response + 4 + 12, resp_len - 12,
                                   &resp_plaintext, &resp_plaintext_len) != 0:
            free(msg_buffer)
            raise RuntimeError("Failed to decrypt response")
        print(f"Decrypted response: {(<char *>resp_plaintext)[:resp_plaintext_len]}")
        free(resp_plaintext)
        free(msg_buffer)