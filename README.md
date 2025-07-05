# Introduction

E2EE Security implements the Signal protocol and aims to make it easy to build versatile end-to-end messaging applications. The two crucial security properties provided:

- End-to-end encryption

  Only sender and recipient (and not even the server) can decrypt the content.

- Forward secrecy

  Past sessions are protected against future compromises of keys or passwords.

E2EE Security software architecture

<p align="center">
  <img src="https://raw.githubusercontent.com/e2eelab/e2ee-security-whitepaper/28292b0fa0ccf19cff3def20901407dfe55ac661/img/e2ee_security_architecture.svg" width="480" />
</p>

# Build

```bash
mkdir build
cd build
cmake ..
make -j8
```

# Test

```bash
cd build/tests
ctest
```

# Doc

[E2EE Security Whitepaper](https://www.e2eelab.org/docs/e2ee-security-whitepaper.git)

# Licensing

E2EE Security is available under two licenses:

- GPLv3, for the growing ecosystem of Free and Open Source Software.
- Commercial, for use in closed-source projects.

For commercial license without the source code conveying liability or any other questions,
please contact <ziv@citi.sinica.edu.tw>.
