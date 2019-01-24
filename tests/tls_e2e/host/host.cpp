// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h> 
#include "tls_e2e_u.h"

#define SERVER_PORT "12345"
#define SERVER_IP "127.0.0.1"

int server_thread_exit_code = OE_OK;
pthread_mutex_t mutex;
pthread_cond_t cond;
bool condition = false;

int server_is_ready()
{
    printf("TLS server_is_ready!\n");
    pthread_mutex_lock(&mutex);
    condition = true;
    pthread_cond_signal(&cond); // Should wake up *one* thread
    pthread_mutex_unlock(&mutex);
    return 1;
}

oe_result_t enclave_identity_verifier(oe_identity_t* identity, void* arg)
{
    oe_result_t result = OE_VERIFY_FAILED;

    (void)arg;
    printf("enclave_identity_verifier is called with parsed report:\n");

    // Check the enclave's security version
    printf("identity.security_version = %d\n", identity->security_version);
    if (identity->security_version < 1)
    {
        printf("identity.security_version check failed (%d)\n", identity->security_version);
        goto done;
    }

    // the unique ID for the enclave
    // For SGX enclaves, this is the MRENCLAVE value
    printf("identity->signer_id :\n");
    for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++)
    {
        printf("0x%0x ", (uint8_t)identity->signer_id[i]);
    }

    // The signer ID for the enclave.
    // For SGX enclaves, this is the MRSIGNER value
    printf("\nidentity->signer_id :\n");
    for (int i = 0; i < OE_SIGNER_ID_SIZE; i++)
    {
        printf("0x%0x ", (uint8_t)identity->signer_id[i]);
    }
    
    // The Product ID for the enclave.
    // For SGX enclaves, this is the ISVPRODID value
    printf("\nidentity->product_id :\n");
    for (int i = 0; i < OE_PRODUCT_ID_SIZE; i++)
    {
        printf("0x%0x ", (uint8_t)identity->product_id[i]);
    }
    result = OE_OK;
done:
    return result;
}

void *server_thread(void *arg) 
{
    oe_result_t result = OE_FAILURE;
    oe_enclave_t* enclave = (oe_enclave_t*)arg;

    printf("Server thread starting\n"); 
    condition = false;
    result = setup_tls_server(enclave, &server_thread_exit_code, (char *)SERVER_PORT);
    if ((result != OE_OK) || server_thread_exit_code)
        oe_put_err("setup_tls_server() failed: result=%u ret=%d", result, server_thread_exit_code);

    printf("Leaving thread...\n"); 
    pthread_exit((void*)&server_thread_exit_code);
} 

int main(int argc, const char* argv[])
{
    oe_result_t result = OE_FAILURE;
    int ret = 0;
    oe_enclave_t* server_enclave = NULL;
    oe_enclave_t* client_enclave = NULL;
    const uint32_t flags = oe_get_create_flags();
    pthread_t server_thread_id;
    pthread_attr_t server_tattr;
    void *retval = NULL;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s server_enc client_enc\n", argv[0]);
        goto exit;
    }

    if ((result = oe_create_tls_e2e_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &server_enclave)) != OE_OK)
    {
        oe_put_err("oe_create_enclave(): result=%u", result);
    }

    if ((result = oe_create_tls_e2e_enclave(
             argv[2], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &client_enclave)) != OE_OK)
    {
        oe_put_err("oe_create_enclave(): result=%u", result);
    }

    // create server thread
    ret = pthread_attr_init(&server_tattr);
    if (ret)
        oe_put_err("pthread_attr_init(server): ret=%u", ret);

    ret = pthread_create(&server_thread_id, NULL, server_thread, (void *)server_enclave);
    if (ret)
        oe_put_err("pthread_create(server): ret=%u", ret);

    printf("wait until TLS server is ready to accept client request\n");
    pthread_mutex_lock(&mutex);
    while(!condition)
        pthread_cond_wait(&cond, &mutex);
    // Thread stuff here
    pthread_mutex_unlock(&mutex);

    // start client
    printf("Starting client\n"); 
    result = launch_tls_client(client_enclave, &ret, (char *)SERVER_IP, (char *)SERVER_PORT);
    if ((result != OE_OK) || ret)
        oe_put_err("client_enclave() failed: result=%u ret=%d", result, ret);

    // block main thread until the server thread is done
    pthread_join(server_thread_id, (void**)&retval);
    printf("server returns retval = [%d]\n", *(int*)retval);

exit:
    result = oe_terminate_enclave(client_enclave);
    OE_TEST(result == OE_OK);

    result = oe_terminate_enclave(server_enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (tls)\n");

    return 0;
}
