/*
 * Author: Marcel Asio
 * Created at: 2015-04-03 13:13:43 +0200
 *
 */

SET client_min_messages = warning;

BEGIN;

drop function verify_totp(text, int, text);
drop function generate_totp(text, int);
drop function perl_hmac(text, text);
drop function unpack(text);
drop function pack(text);
drop function provisioning_url(text, text, int, text);
drop function urlencode(text);
drop function random_base32(int);
drop language plperlu;

COMMIT;
