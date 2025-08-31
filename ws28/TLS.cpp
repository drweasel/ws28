#include "TLS.h"

namespace
{
void
initialise_SSL()
{
    static std::once_flag f;
    std::call_once(
      f,
      []()
      {
          SSL_library_init();
          OpenSSL_add_all_algorithms();
          SSL_load_error_strings();
#if OPENSSL_VERSION_NUMBER < 0x30000000L || defined(LIBRESSL_VERSION_NUMBER)
          ERR_load_BIO_strings();
#endif
          ERR_load_crypto_strings();
      });
}

SSL_CTX *
create_context()
{
    const SSL_METHOD *method = TLS_server_method();
    return SSL_CTX_new(method);
}

void
throw_SSL_error()
{
    char buf[256] = { 0 };
    ERR_error_string(ERR_get_error(), buf);
    throw std::runtime_error(buf);
}

void
configure_SSL_context(
  SSL_CTX *ctx,
  const std::filesystem::path &key_file,
  const std::filesystem::path &crt_file)
{
    ERR_clear_error();
    if (
      SSL_CTX_use_PrivateKey_file(
        ctx, key_file.generic_string().c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        throw_SSL_error();
    }
    if (
      SSL_CTX_use_certificate_file(
        ctx, crt_file.generic_string().c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        throw_SSL_error();
    }

    if (SSL_CTX_check_private_key(ctx) != 1)
    {
        throw_SSL_error();
    }
}
} // namespace

namespace ws28
{
int
SSLServerContext::password_callback(
  char *buf,
  int size,
  int rwflag,
  void *userdata)
{
    auto *self = reinterpret_cast< ws28::SSLServerContext * >(userdata);

    if (!self)
        return 0; // invalid user data

    std::string password = self->key_password_cb_();
    if (int(password.size()) > size - 1)
        return 0; // Not enough space
    std::memcpy(buf, password.data(), password.size());
    return int(password.size());
}

SSLServerContext::SSLServerContext(
  const std::filesystem::path &key_file,
  const std::filesystem::path &crt_file,
  std::function< std::string() > key_password_cb)
  : ctx_(create_context())
  , key_password_cb_(key_password_cb)

{
    initialise_SSL();

    if (ctx_)
    {
        if (key_password_cb_)
        {
            SSL_CTX_set_default_passwd_cb_userdata(ctx_, this);
            SSL_CTX_set_default_passwd_cb(ctx_, password_callback);
        }

        configure_SSL_context(ctx_, key_file, crt_file);
    }
}

SSLServerContext::~SSLServerContext()
{
    if (ctx_)
        SSL_CTX_free(ctx_);
}

TLS::TLS(SSL_CTX *ctx, bool server, const char *hostname)
{
    m_ReadBIO = BIO_new(BIO_s_mem());
    m_WriteBIO = BIO_new(BIO_s_mem());
    m_SSL = SSL_new(ctx);

    if (server)
    {
        SSL_set_accept_state(m_SSL);
    }
    else
    {
        SSL_set_connect_state(m_SSL);
    }

    if (!server && hostname)
        SSL_set_tlsext_host_name(m_SSL, hostname);
    SSL_set_bio(m_SSL, m_ReadBIO, m_WriteBIO);

    if (!server)
        doSSLHandshake();
}

bool
TLS::Write(const char *buf, size_t len)
{
    m_EncryptBuf.insert(m_EncryptBuf.end(), buf, buf + len);
    return doEncrypt();
}
TLS::SSLStatus
TLS::getSSLStatus(int n)
{
    switch (SSL_get_error(m_SSL, n))
    {
    case SSL_ERROR_NONE:
        return SSLStatus::OK;

    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
        return SSLStatus::WANT_IO;

    case SSL_ERROR_ZERO_RETURN:
    case SSL_ERROR_SYSCALL:
    default:
        return SSLStatus::FAIL;
    }
}

void
TLS::queueEncrypted(const char *buf, size_t len)
{
    m_WriteBuf.insert(m_WriteBuf.end(), buf, buf + len);
}

bool
TLS::doEncrypt()
{
    if (!SSL_is_init_finished(m_SSL))
        return true;

    int n;

    while (!m_EncryptBuf.empty())
    {
        ERR_clear_error();
        n = SSL_write(m_SSL, m_EncryptBuf.data(), (int)m_EncryptBuf.size());

        if (getSSLStatus(n) == SSLStatus::FAIL)
            return false;

        if (n > 0)
        {
            // Consume bytes
            m_EncryptBuf.erase(m_EncryptBuf.begin(), m_EncryptBuf.begin() + n);

            // Write them out
            do
            {
                char buf[4096];
                n = BIO_read(m_WriteBIO, buf, sizeof buf);
                if (n > 0)
                {
                    queueEncrypted(buf, n);
                }
                else if (!BIO_should_retry(m_WriteBIO))
                {
                    return false;
                }
            } while (n > 0);
        }
    }

    return true;
}

TLS::SSLStatus
TLS::doSSLHandshake()
{
    ERR_clear_error();
    SSLStatus status = getSSLStatus(SSL_do_handshake(m_SSL));

    // Did SSL request to write bytes?
    if (status == SSLStatus::WANT_IO)
    {
        int n;
        do
        {
            char buf[4096];
            n = BIO_read(m_WriteBIO, buf, sizeof buf);

            if (n > 0)
            {
                queueEncrypted(buf, n);
            }
            else if (!BIO_should_retry(m_WriteBIO))
            {
                return SSLStatus::FAIL;
            }

        } while (n > 0);
    }

    return status;
}

} // namespace ws28
