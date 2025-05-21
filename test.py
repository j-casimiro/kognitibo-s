from auth import get_password_hash, verify_password, verify_email, create_access_token, decode_access_token, is_token_expired

def test_get_password_hash():
    password = 'test'
    hashed_password = get_password_hash(password)
    assert hashed_password is not None
    assert hashed_password != password


def test_verify_password():
    password = 'test'
    hashed_password = get_password_hash(password)
    assert verify_password(password, hashed_password) == True


def test_verify_email():
    email = 'test@test.com'
    assert verify_email(email) == True


def test_create_access_token():
    data = {'sub': 'test'}
    token = create_access_token(data)
    assert token is not None
    assert token != ''


def test_decode_access_token():
    data = {'sub': 'test'}
    token = create_access_token(data)
    decoded_data = decode_access_token(token)
    assert decoded_data is not None
    assert decoded_data['sub'] == 'test'
