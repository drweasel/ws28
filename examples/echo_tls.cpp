#include "ws28/Server.h"
#include "ws28/ScopeGuard.h"

#include <openssl/ssl.h>

#include <sstream>

SSL_CTX *
create_SSL_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

#define STRINGIFY(s) STRINGIFY_(s)
#define STRINGIFY_(s) #s

int
password_callback(char *buf, int size, int rwflag, void *userdata)
{
    char password[] = STRINGIFY(ECHO_SERVER_PEM_PASSWORD);

    if (int(sizeof(password)) > size - 1)
        return 0; // Not enough space

    std::memcpy(buf, password, sizeof(password));

    return (int)sizeof(password);
}

void
configure_SSL_context(SSL_CTX *ctx)
{
    // Load the server's certificate
    if (
      SSL_CTX_use_certificate_file(ctx, "echo_server.crt", SSL_FILETYPE_PEM) <=
      0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load the server's private key
    if (
      SSL_CTX_use_PrivateKey_file(ctx, "echo_server.key", SSL_FILETYPE_PEM) <=
      0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify that the private key matches the public certificate
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(EXIT_FAILURE);
    }
}

int
main()
{
    static volatile sig_atomic_t quit = false;

    // OPENSSL_init_ssl(0, nullptr);
    // SSL_load_error_strings();
    ws28::TLS::InitSSL();

    SSL_CTX *ssl_ctx = create_SSL_context();

    ScopeGuard ssl_ctx_guard = [&] { SSL_CTX_free(ssl_ctx); };

    SSL_CTX_set_default_passwd_cb(ssl_ctx, password_callback);

    configure_SSL_context(ssl_ctx);

    signal(
      SIGINT,
      [](int)
      {
          if (quit)
          {
              exit(EXIT_FAILURE);
          }
          else
          {
              quit = true;
          }
      });

    ws28::Server s{ uv_default_loop(), ssl_ctx };

    static intptr_t userID = 0;

    // I recommend against setting these limits, they're way too high and allow
    // easy DDoSes. Use the default settings. These are just here to pass tests
    s.SetMaxMessageSize(256 * 1024 * 1024); // 256 MB

    s.SetClientConnectedCallback(
      [](ws28::Client *client, ws28::HTTPRequest &)
      {
          client->SetUserData((void *)++userID);
          // printf("Client %d connected\n", (int) userID);
      });

    s.SetClientDisconnectedCallback(
      [](ws28::Client *client)
      {
          // printf("Client %d disconnected\n", (int) (intptr_t)
          // client->GetUserData());
      });

    s.SetClientDataCallback(
      [](ws28::Client *client, char *data, size_t len, int opcode)
      {
          // printf("Client %d: %.*s\n", (int) (intptr_t) client->GetUserData(),
          // (int) len, data);
          client->Send(data, len, opcode);
      });

    s.SetHTTPCallback(
      [](ws28::HTTPRequest &req, ws28::HTTPResponse &res)
      {
          std::stringstream ss;
          ss << "Hi, you issued a " << req.method << " to " << req.path
             << "\r\n";
          ss << "Headers:\r\n";

          req.headers.ForEach([&](std::string_view key, std::string_view value)
                              { ss << key << ": " << value << "\r\n"; });

          res.send(ss.str());
      });

    uv_timer_t timer;
    uv_timer_init(uv_default_loop(), &timer);
    timer.data = &s;
    uv_timer_start(
      &timer,
      [](uv_timer_t *timer)
      {
          if (quit)
          {
              puts(
                "Waiting for clients to disconnect, send another SIGINT to "
                "force quit");
              auto &s = *(ws28::Server *)(timer->data);
              s.StopListening();
              uv_timer_stop(timer);
              uv_close((uv_handle_t *)timer, nullptr);
          }
      },
      10,
      10);

    assert(s.Listen(3000));

    puts("Listening");
    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
    assert(uv_loop_close(uv_default_loop()) == 0);
    puts("Clean quit");

    return EXIT_SUCCESS;
}
