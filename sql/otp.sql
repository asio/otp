/*
 * Author: Marcel Asio
 * Created at: 2015-04-03 13:13:43 +0200
 *
 */

SET client_min_messages = warning;

create language plperlu;

create function random_base32(_length int default 16)
    returns text
    language sql as $$
    SELECT
        string_agg(('{a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,2,3,4,5,6,7}'::text[])[ceil(random() * 32)], '')
    FROM generate_series(1, _length);
$$;

create function urlencode(in_str text)
    returns text
    language plpgsql
    strict immutable as $$
declare
    _i      int4;
    _temp   varchar;
    _ascii  int4;
    _result text := '';
begin
    for _i in 1 .. length(in_str) loop
        _temp := substr(in_str, _i, 1);
        if _temp ~ '[0-9a-zA-Z:/@._?#-]+' then
            _result := _result || _temp;
        else
            _ascii := ascii(_temp);
            if _ascii > x'07ff'::int4 then
                raise exception 'won''t deal with 3 (or more) byte sequences.';
            end if;
            if _ascii <= x'07f'::int4 then
                _temp := '%'||to_hex(_ascii);
            else
                _temp := '%'||to_hex((_ascii & x'03f'::int4)+x'80'::int4);
                _ascii := _ascii >> 6;
                _temp := '%'||to_hex((_ascii & x'01f'::int4)+x'c0'::int4)
                            ||_temp;
            end if;
            _result := _result || upper(_temp);
        end if;
    end loop;
    return _result;
end;
$$;

create function provisioning_url(_email text, _secret text, _interval int, _issuer text)
    returns text
    language sql
    strict immutable as $$
    select concat(
            'otpauth://totp/', urlencode(_email),
            '?secret=',        urlencode(_secret),
            '&period=',        urlencode(_interval::text),
            '&issuer=',        urlencode(_issuer)
    );
$$;

create function pack(text)
    returns text
    language plperlu as $$
    return pack("B*", shift);
$$;

create function unpack(text)
    returns text
    language plperlu as $$
    return unpack("H*", shift);
$$;

create function perl_hmac(text, text)
    returns text
    language plperlu as $$
    use Digest::HMAC_SHA1 qw/ hmac_sha1_hex /;
    return hmac_sha1_hex(pack("H*", shift), pack("H*", shift));
$$;

create function generate_totp(_secret text, _interval int default 30, _length int default 6)
    returns text
    language plpgsql as $$
declare
    _input_check int := length(_secret) % 8;
    _buffer      text := '';
    _b32_secret  text;
    _key         text;
    _lpad_time   text := lpad(to_hex(floor(extract(epoch from now()) / _interval)::int), 16, '0');
    _hmac        text;
    _offset      int;
    _part1       int;
begin
    IF NOT _secret ~ '^[a-z2-7]+$' THEN
        RAISE EXCEPTION 'Data contains non-base32 characters';
    END IF;

    IF _input_check = 1 OR _input_check = 3 OR _input_check = 8 THEN
        RAISE EXCEPTION 'Length of data invalid';
    END IF;

    with chars2bits AS (
        select
            character,
            (index - 1)::bit(5)::text AS index
        from unnest('{a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,2,3,4,5,6,7}'::text[]) with ordinality as t (character, index)
    )
    select string_agg(c.index, '') INTO _buffer
    from regexp_split_to_table(_secret, '') s
    inner join chars2bits c ON (s = c.character);

    IF NOT _buffer ~ ('0{' || length(_buffer) % 8 || '}$') THEN
        RAISE EXCEPTION 'PADDING number of bits at the end of output buffer are not all zero';
    END IF;

    _b32_secret := pack(_buffer);
    _key        := unpack(_b32_secret);
    _hmac       := perl_hmac(_lpad_time, _key);

    select ('x' || lpad(substring(_hmac from '.$'), 8, '0'))::bit(32)::int INTO _offset;
    select ('x' || lpad(substring(_hmac, _offset * 2 + 1, 8), 8, '0'))::bit(32)::int INTO _part1;

    RETURN substring((_part1 & x'7fffffff'::int)::text from '.{' || _length || '}$');
end;
$$;

create function verify_totp(_secret text, _interval int, _otp text)
    returns boolean
    language sql as $$
    SELECT generate_totp(_secret, _interval) = _otp;
$$;
