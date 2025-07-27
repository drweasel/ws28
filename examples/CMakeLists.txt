add_executable(echo)
target_sources(echo PRIVATE echo.cpp)
target_link_libraries(echo ws28)

set(WS28_CA_DAYS 3650)
set(WS28_CA_PASSWORD "Ree5pohLui")
set(WS28_CA_CNF "${CMAKE_CURRENT_LIST_DIR}/ws28_ca.cnf")

set(ECHO_SERVER_DAYS 3650)
set(ECHO_SERVER_PASSWORD "eegh8Zai0b")
set(ECHO_SERVER_CNF "${CMAKE_CURRENT_LIST_DIR}/echo_server.cnf")

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/ws28_ca.crt
  COMMAND openssl req -x509 -new -newkey rsa:4096 -days ${WS28_CA_DAYS} -keyout ${CMAKE_CURRENT_BINARY_DIR}/ws28_ca.key -out ${CMAKE_CURRENT_BINARY_DIR}/ws28_ca.crt -passout pass:${WS28_CA_PASSWORD} -config ${WS28_CA_CNF}
)

add_custom_target(ws28_ca
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/ws28_ca.crt
  VERBATIM
  )

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/echo_server.key
  COMMAND openssl req -new -newkey rsa:4096 -keyout ${CMAKE_CURRENT_BINARY_DIR}/echo_server.key -out ${CMAKE_CURRENT_BINARY_DIR}/echo_server.csr -passout pass:${ECHO_SERVER_PASSWORD} -config ${ECHO_SERVER_CNF}
  COMMAND openssl x509 -req -in ${CMAKE_CURRENT_BINARY_DIR}/echo_server.csr -CA ${CMAKE_CURRENT_BINARY_DIR}/ws28_ca.crt -CAkey ${CMAKE_CURRENT_BINARY_DIR}/ws28_ca.key -CAcreateserial -out ${CMAKE_CURRENT_BINARY_DIR}/echo_server.crt -days ${ECHO_SERVER_DAYS} -passin pass:${WS28_CA_PASSWORD} -extfile ${WS28_CA_CNF}
)

add_custom_target(echo_server_pem
  DEPENDS ws28_ca
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/echo_server.key
  VERBATIM
  )

add_executable(echo_tls)
target_sources(echo_tls PRIVATE echo_tls.cpp)
target_link_libraries(echo_tls ws28)
add_dependencies(echo_tls echo_server_pem)
target_compile_definitions(echo_tls PRIVATE ECHO_SERVER_PEM_PASSWORD=${ECHO_SERVER_PASSWORD})

