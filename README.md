# go-rsa-util

A handful of convenient functions for interacting with rsa public/private keys (mostly just code examples for quickly referencing the details of how to do certain things)

Note: This only supports ssh-keygen generated keys (pkcs1).  I tried to get openssl keys to work too, but had trouble getting go to load the private keys.

## Formatting, Building, etc.

```
make
```

## Generating Coverage Report

```
make coverage-html
open _coverage/coverage.html
```

## Publishing Changes

```
git push origin master
git tag v0.0.0 # supply the correct semantic version
git push origin v0.0.0
```

## Generating Keys To Test With

### SSH KeyGen

```
ssh-keygen -t rsa -m PEM -f ssh-keygen.key.pem
ssh-keygen -f ssh-keygen.key.pem -e -m pem > ssh-keygen.pub.pem
```
