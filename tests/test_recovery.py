import hashlib
import os
import re
import tempfile
import unittest
from unittest.mock import patch


class RecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.env = patch.dict(os.environ, {
            "DB_PATH": os.path.join(cls.temp.name, "test.sqlite"),
            "GEMINI_API_KEY": "local-test-key",
            "SECRET_KEY": "test-only-key",
            "RATELIMIT_ENABLED": "False",
        })
        cls.env.start()
        import app as service
        cls.service = service
        service.app.testing = True
        service.limiter.enabled = False

    @classmethod
    def tearDownClass(cls):
        cls.env.stop()
        cls.temp.cleanup()

    def setUp(self):
        self.client = self.service.app.test_client()
        self.guest = self.service.app.test_client()
        self.code = "나만-기억할-열두글자-코드"
        self.username = self._testMethodName[-18:]
        with self.service.get_db() as db:
            db.execute("INSERT INTO users(username,password) VALUES (?,?)",
                       (self.username, hashlib.sha256(b"original").hexdigest()))
        res = self.login(self.client, "original")
        self.assertEqual(res.status_code, 200)

    def login(self, client, password):
        return client.post("/api/login", json={"username": self.username, "password": password})

    def post_form(self, client, path, **data):
        html = client.get(path).get_data(as_text=True)
        csrf = re.search(r'name="csrf" value="([^"]+)"', html)[1]
        return client.post(path, data={**data, "csrf": csrf})

    def setup_code(self, code):
        return self.post_form(self.client, "/account/recovery-code", password="original", code=code, confirm=code)

    def verify(self, client, code):
        return self.post_form(client, "/forgot-password", username=self.username, code=code)

    def test_reset_and_replay(self):
        self.assertEqual(self.setup_code(self.code).status_code, 303)
        other = self.service.app.test_client()
        self.assertEqual(self.verify(other, self.code).status_code, 303)
        self.assertEqual(self.verify(self.guest, self.code).status_code, 303)
        fields = {"password": "replacement", "confirm": "replacement"}
        self.assertEqual(self.post_form(self.guest, "/reset-password", **fields).status_code, 200)
        self.assertEqual(self.post_form(other, "/reset-password", **fields).status_code, 400)
        self.assertEqual(self.verify(self.guest, self.code).status_code, 400)
        self.assertEqual(self.client.get("/api/me").status_code, 401)
        self.assertEqual(self.login(self.guest, "original").status_code, 401)
        self.assertEqual(self.login(self.guest, "replacement").status_code, 200)

    def test_six_digit_code(self):
        code = "038527"
        self.assertEqual(self.setup_code(code[:5]).status_code, 400)
        setup = self.client.get("/account/recovery-code").get_data(as_text=True)
        verify = self.guest.get("/forgot-password").get_data(as_text=True)
        for form in (setup, verify):
            self.assertRegex(form, r'name="code"[^>]*minlength="6"')
        self.assertEqual(self.setup_code(code).status_code, 303)
        self.assertEqual(self.verify(self.guest, code).status_code, 303)
        result = self.post_form(self.guest, "/reset-password", password="changed", confirm="changed")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.login(self.guest, "changed").status_code, 200)

    def test_rotation_and_expiry(self):
        self.assertEqual(self.setup_code(self.code).status_code, 303)
        self.assertEqual(self.verify(self.guest, self.code).status_code, 303)
        new_code = self.code + "-새값"
        self.assertEqual(self.setup_code(new_code).status_code, 303)
        self.assertEqual(self.post_form(self.guest, "/reset-password", password="next", confirm="next").status_code, 400)
        self.assertEqual(self.verify(self.guest, self.code).status_code, 400)
        self.assertEqual(self.verify(self.guest, new_code).status_code, 303)
        with self.guest.session_transaction() as sess:
            sess["reset_grant"] = {**sess["reset_grant"], "expires": 0}
        self.assertEqual(self.guest.post("/reset-password").location, "/forgot-password")

    def test_setup_requires_owner(self):
        self.assertEqual(self.guest.get("/account/recovery-code").location, "/login")
        self.assertEqual(self.client.post("/account/recovery-code").status_code, 403)
        self.assertEqual(self.post_form(self.client, "/account/recovery-code",
                                       password="wrong", code=self.code, confirm=self.code).status_code, 400)
        self.assertEqual(self.verify(self.guest, self.code).status_code, 400)
        self.assertEqual(self.guest.post("/reset-password").location, "/forgot-password")
        self.assertEqual(self.setup_code("1234").status_code, 400)

    def test_new_account_can_enroll_after_login(self):
        fresh = self.service.app.test_client()
        result = fresh.post("/api/register", json={"username": "fresh", "password": "chosen-pass"})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(fresh.get("/account/recovery-code").location, "/login")
        fresh.post("/api/login", json={"username": "fresh", "password": "chosen-pass"})
        res = self.post_form(fresh, "/account/recovery-code", password="chosen-pass",
                             code=self.code, confirm=self.code)
        self.assertEqual(res.status_code, 303)
