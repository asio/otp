otp
===

Description
-----------

Implementation of TOTP which is compatible with google authenticator app.

Usage
-----

```sql
CREATE EXTENSION otp;

CREATE TABLE users (
  email text not null,
  secret   text not null,
  interval int not null default 30,
  length   int not null default 6
);
INSERT INTO users (email, secret) VALUES ('foo@example.com', random_base32());

SELECT generate_totp(secret, interval, length)
FROM users WHERE email = 'foo@example.com';

SELECT verify_totp(secret, interval, '380092')
FROM users
WHERE email = 'foo@example.com';

SELECT provisioning_url(email, secret, interval, 'Company Name')
FROM users
WHERE email = 'foo@example.com';
```

Author
------

Marcel Asio

Copyright and License
---------------------

Copyright (c) 2015 Marcel Asio.
