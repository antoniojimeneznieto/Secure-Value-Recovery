## Outline of this document

1. Background
2. Goals
3. General Description
4. Key Steps

## Context

The first goal of this project is to develop a large program in C on a "system" theme.  

The management of confidential data in the cloud is one of the major issues of our time. We only have to read the newspapers to understand the issues related to massive data loss when managed centrally, whether in local servers or in the cloud.

Password management is a good example.  The site [haveibeenpwned](https://haveibeenpwned.com/) aggregates a collection of data stolen from over 500 websites, totaling 11 billion accounts.  Your email may be one of them, by the way.

Ideally, confidential data is never available in a centralized site. Communication systems with end-to-end encryption ensure that relay servers cannot decrypt the content of messages. The mobile applications [SIGNAL](https://en.wikipedia.org/wiki/Signal_(software)) and WhatsApp are two well-known examples; both use variants of the same cryptographic protocol.

SIGNAL is particularly well known for its maximum privacy.  The goal of the foundation that operates it is to offer a global deployment service (over 40 million active users) while minimizing the information collected by their servers (see [Wikipedia](https://en.wikipedia.org/wiki/Signal_(software))).

SIGNAL has introduced a new feature that allows a user to copy their contact list to the cloud.  This feature is useful if you have to change your phone. The list is protected by a 6 digit PIN.  If you are a user of the mobile application, it asks you to enter the PIN regularly to make sure you don't forget it.

The underlying technology is called "_secure value recovery_" and is described here: [https://signal.org/blog/secure-value-recovery/](https://signal.org/blog/secure-value-recovery/).   This solution uses a number of advanced technologies from various fields such as cryptography, hardware (SGX enclaves) and even required a compiler modification.


## Goals

During this project, we will build a simplified version of "secure value recovery" that encrypts data in a shared database: a "_(en)crypted key-value store" (hence the project name: "CryptKVS").

**IMPORTANT SECURITY NOTE:** for simplicity, the solution we will implement is not resistant to brute force attacks, as explained below.  In security, any simplification or change has side effects that must be analyzed in detail. This is not the objective of this course.

The main educational objective is to give an overview of the tools and techniques for building system-oriented programming, including basic cryptographic libraries, but this is not a computer security course. **end of note]**


During the first few weeks, the focus will be on implementing the basic system functions, namely:

* list information (metadata, data list) ;
* decrypt a value when the key and the password are known;
* create a key and associate a corresponding value.

In this first phase, the functions will be exposed via a command line utility. During the last weeks of the semester, we will build a real web server that will expose the same functionality by separating the client and server functions.


During this project, we will be able to practice and discover:

* C programming in a medium-sized project;
* debugging tools presented during the first 3 weeks (`gdb`, `asan`, etc.); the emphasis will be on correct memory management (allocation, deallocation, bounds checking);
* file management with the POSIX library;
* the cryptographic library `openssl` ;
* client-server programming in C using `libcurl` (client side) and `libmongoose` (server side) ;
* the `https` protocol and the management of SSL certificates.


During the 10 weeks of this project, we will have to implement, gradually piece by piece, the key components mentioned above and described below, then detailed in the weekly topics.

We will also have to develop additional tests that are useful for observing and analyzing the operation of the system. These tests will be developed as executables independent of the main core.

In order to facilitate the organization of your work (in the group and in time), we advise you to consult [the course schedule page](/project/bareme.html) (and read it in its entirety!!).


## General description

We describe here in a general way the main concepts and data structures that this project will require. Their implementation details will be specified later when necessary in each corresponding weekly topic.


Consider the problem of storing a secret in the cloud. Each secret has :

* a unique key (`key`), e.g. the user's name, phone number, etc.  
    In our solution, this is a string of up to 32 characters (not including `'\0'`); it is the only element visible in clear text in the database;

* a password, known only to the user; the combination of the key and the password form the basis of a double cryptographic string used to:

    1. verify that the password is correct and
    2. encrypting and decrypting the content;

* the secret itself (i.e. the value). The main objective is to protect the content, so that only the client can recover it.

The solution is based on the SIGNAL "_secure value recovery_" protocol, which is described as follows (explained below):

```
stretched_key = Argon2(passphrase=user_passphrase, output_length=32)

auth_key = HMAC-SHA256(key=stretched_key, "Auth Key")
c1 = HMAC-SHA256(key=stretched_key, "Master Key Encryption")
c2 = Secure-Random(output_length=32)

master_key = HMAC-SHA256(key=c1, c2)
```

Obviously, this notation requires some explanation:

* `user_passphrase` is the concatenation of the key (`key`) and the password (`password`); in the original protocol, the concatenation is then "stretched" to 32 bytes by the `Argon2` cryptographic function; this operation takes place on the client; for simplicity, we just do the concatenation (without `Argon2`);

* the client then generates `auth_key` and `c1`, using `stretched_key` to digitally sign two `documents`; these `documents` are constants with ``Auth key`` and ``Master Key Encryption`` contents respectively;  
    the content is not important -- since these are protocol constants; the important thing is that they are two _different_ documents, making it impossible for an adversary to link one result with the other.

* the server generates the `c2` value randomly (32 bytes); it stores in a table `key`, `auth_key` and `c2` ;

* when the client wants to read or write a value, the client submits `auth_key` as authentication; the server responds with `c2` ;

* only the client can generate `master_key`, which is then used by the client as a symmetric key to encrypt (write) or decrypt (read) the value.


This protocol has a number of interesting properties, available in the SIGNAL solution (and not in the project):

* the entropy offered by `c2` in `master_key` implies that an attacker with unlimited means could not decode the secret values unless he has access to `c2` ;    
    the secrets can therefore be stored in the cloud (e.g. on disk) as long as `c2` is protected, which is the case with the use of SGX enclaves; in our project, to simplify everything is stored in the same file;

* in the version deployed by SIGNAL, the service limits the number of attempts to compare `auth_key`, which avoids a brute force attack.


## Project Development Steps

* Week 4 (this week!): the "stats" command: a read operation to access the disk format of the database.

* Week 5: "get" command: implement the logic to compute the various keys and decode a secret stored in the provided file. exercises the openssl library functions, etc.

* Week 6 : command " set " : requires fseek, fwrite, to append the new value and update an existing entry.

* Week 7: command " new " : create a new key.  This is where we introduce open hashing instead of linear scan. Move away from fixed-sized tables to a dynamic approach where the table size is set in the header.

* Week 9: refactoring the CLI to be table-driven; also preparation for client-server programming; (students will probably not be asked to implement "create-kvs" to create a table).

* Week 10: "stat"/network and "get"/network commands: instructors provide the running server (shared by all).   Programming HTTP clients.  Requires mongoose.

* Week 11: "httpd" command: students connect to their own web server.   Students implement "stat"/network "get"/network.

* Week 12: "set"/network and "new"/network commands (client and server side).  For simplicity, "set" is implemented using "GET" rather than "POST" (little secrets only); more advanced students can of course implement a "POST".
