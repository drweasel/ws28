#pragma once

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <concepts>
#include <filesystem>
#include <functional>
#include <vector>

namespace ws28
{

class SSLServerContext
{

private:
    SSL_CTX *ctx_ = nullptr;
    std::function< std::string() > key_password_cb_;

    static int password_callback(char *, int, int, void *);

public:
    SSLServerContext(
      const std::filesystem::path &key_file,
      const std::filesystem::path &crt_file,
      std::function< std::string() > key_password_cb = nullptr);

    SSLServerContext(SSLServerContext &&) = default;
    SSLServerContext &operator=(SSLServerContext &&) = default;
    SSLServerContext(const SSLServerContext &) = delete;
    SSLServerContext &operator=(const SSLServerContext &) = delete;

    SSL_CTX *Get() { return ctx_; }

    ~SSLServerContext();
};

// Ported from https://github.com/darrenjs/openssl_examples
// MIT licensed
class TLS
{
    enum class SSLStatus
    {
        OK,
        WANT_IO,
        FAIL
    };

public:
    TLS(SSL_CTX *ctx, bool server = true, const char *hostname = nullptr);

    ~TLS() { SSL_free(m_SSL); }

    TLS(TLS &&) = default;
    TLS &operator=(TLS &&) = default;
    TLS(const TLS &) = delete;
    TLS &operator=(const TLS &) = delete;

    /**
     * Writes unencrypted bytes to be encrypted and sent out.
     * If this returns false, the connection must be closed.
     */
    bool Write(const char *buf, size_t len);

    /**
     * Process raw bytes received from the other side.
     * If this returns false, the connection must be closed
     */
    template< std::invocable< char *, size_t > F >
    bool ReceivedData(const char *src, size_t len, const F &f)
    {
        int n;
        while (len > 0)
        {
            n = BIO_write(m_ReadBIO, src, len);

            // Assume bio write failure is unrecoverable
            if (n <= 0)
                return false;

            src += n;
            len -= n;

            if (!SSL_is_init_finished(m_SSL))
            {
                if (doSSLHandshake() == SSLStatus::FAIL)
                    return false;
                if (!SSL_is_init_finished(m_SSL))
                    return true;
            }

            ERR_clear_error();
            do
            {
                char buf[4096];
                n = SSL_read(m_SSL, buf, sizeof buf);
                if (n > 0)
                {
                    f(buf, (size_t)n);
                }
            } while (n > 0);

            auto status = getSSLStatus(n);
            if (status == SSLStatus::WANT_IO)
            {
                do
                {
                    char buf[4096];
                    n = BIO_read(m_WriteBIO, buf, sizeof(buf));
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
            else if (status == SSLStatus::FAIL)
            {
                return false;
            }
        }

        return true;
    }

    template< std::invocable< char *, size_t > F >
    void ForEachPendingWrite(const F &f)
    {
        // If the callback does something crazy like calling Write inside of it
        // We need to handle this carefully, thus the swap.
        for (;;)
        {
            if (m_WriteBuf.empty())
                return;

            std::vector< char > buf;
            std::swap(buf, m_WriteBuf);

            f(buf.data(), buf.size());
        }
    }

    bool IsHandshakeFinished() { return SSL_is_init_finished(m_SSL); }

private:
    SSLStatus getSSLStatus(int n);

    void queueEncrypted(const char *buf, size_t len);

    bool doEncrypt();

    SSLStatus doSSLHandshake();

    std::vector< char > m_EncryptBuf; // Bytes waiting to be encrypted
    std::vector< char > m_WriteBuf; // Bytes waiting to be written to the socket

    SSL *m_SSL;
    BIO *m_ReadBIO;
    BIO *m_WriteBIO;
};

} // namespace ws28
