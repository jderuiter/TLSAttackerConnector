# TLS-Attacker Connector

This tool provides a connection between TLS-Attacker and StateLearner.

## Build

```
mvn package
```

## Example

Start OpenSSL

```
openssl s_server -key server.key -cert server.crt -CAfile cacert.pem -accept 4433 -HTTP
```

Start TLS-Attacker Connector

```

```

Run StateLearner

```

```