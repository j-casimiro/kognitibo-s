from auth import (get_password_hash, 
                  verify_password, 
                  verify_email,
                  create_access_token, 
                  create_refresh_token,
                  decode_access_token, 
                  decode_refresh_token,
                  is_access_token_expired, 
                  is_refresh_token_expired)


def test_is_access_token_expired():
    token = create_access_token(data={'sub': 'test'})
    assert is_access_token_expired(token) == False


def test_is_refresh_token_expired():
    token = create_refresh_token(data={'sub': 'test'})
    assert is_refresh_token_expired(token) == False


def test_verify_password():
    assert verify_password('password', get_password_hash('password')) == True
    assert verify_password('password', get_password_hash('wrong_password')) == False


def test_verify_email():
    assert verify_email('test@test.com') == True
    assert verify_email('test@test') == False
    assert verify_email('test@test.') == False
    assert verify_email('test@test.com.') == False
    assert verify_email('test@test.com.com') == True
    assert verify_email('test@test.com.com.com') == True
    assert verify_email('test@test.com.com.com.com') == True


def test_create_access_token():
    token = create_access_token(data={'sub': 'test'})
    assert token is not None


def test_create_refresh_token():
    token = create_refresh_token(data={'sub': 'test'})
    assert token is not None


def test_decode_access_token():
    token = create_access_token(data={'sub': 'test'})
    decoded = decode_access_token(token)
    assert decoded is not None
    assert decoded.get('sub') == 'test'
    assert decoded.get('type') == 'access'
    assert 'exp' in decoded
    assert 'iat' in decoded
    assert 'jti' in decoded


def test_decode_refresh_token():
    token = create_refresh_token(data={'sub': 'test'})
    decoded = decode_refresh_token(token)
    assert decoded is not None
    assert decoded.get('sub') == 'test'
    assert decoded.get('type') == 'refresh'
    assert 'exp' in decoded
    assert 'iat' in decoded
    assert 'jti' in decoded


def test_get_password_hash():
    assert get_password_hash('password') is not None
    assert get_password_hash('password') != 'password'

