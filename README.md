# go-rsa-util

A handful of convenient functions for interacting with rsa public/private keys (mostly just code examples for quickly referencing the details of how to do certain things)

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
