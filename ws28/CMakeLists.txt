add_library(ws28 OBJECT)

target_sources(ws28 PRIVATE
  Client.cpp
  Client.h
  HTTPRequestHeaders.h
  ScopeGuard.h
  Server.cpp
  Server.h
  TLS.h
  )

target_include_directories(ws28 PUBLIC
  ${LIBUV_INCLUDE_DIRS}
  )

target_link_libraries(ws28
  PkgConfig::LIBUV
  OpenSSL::SSL
  #OpenSSL::Crypto
  )

