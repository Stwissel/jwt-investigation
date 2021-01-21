# JWT Investigation

## Goal

Generate my own public/private key pairs for authentication using JWT claim

## Setup

On first run 3 files are generated:

- test.crt
- test.private.pem
- test.public.pem

When test.crt is missing, all 3 files get regenerated

## Run

- generate files if missing
- load keys from file
- run test (method `testKeys`)
   - create new JWTAuthOptions
   - add all keys with R256 algo (method `getPubSecOptions`)
   - try to create token
   - try to validate token
   
## Issue

Error:

```
Exception in thread "main" java.lang.RuntimeException: Algorithm not supported: HS256
    at io.vertx.ext.auth.impl.jose.JWT.sign(JWT.java:334)
    at io.vertx.ext.auth.jwt.impl.JWTAuthProviderImpl.generateToken(JWTAuthProviderImpl.java:182)
    at io.vertx.ext.auth.jwt.JWTAuth.generateToken(JWTAuth.java:65)
    at com.notessensei.jwttest.MainVerticle.testKeys(MainVerticle.java:203)
    at com.notessensei.jwttest.MainVerticle.main(MainVerticle.java:65)

```