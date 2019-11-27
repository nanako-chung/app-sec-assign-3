import pytest
from flask import url_for

class TestApp:

    def test_login(self, client):
        res = client.get(url_for('login'))
        assert res.status_code == 200
        assert b"<title>Login</title>" in res.data

    def test_register(self, client):
        res = client.get(url_for('register'))
        assert res.status_code == 200
        assert b"<title>Register</title>" in res.data

    def test_spell_check (self, client):
        res = client.get(url_for('spell_check'))
        assert res.status_code == 302
        assert b"<title>Redirecting...</title>" in res.data