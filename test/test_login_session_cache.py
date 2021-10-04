import json
import os.path
from datetime import datetime, timedelta, timezone

from aws_adfs import login


class TestLoginSessionCache:
    def test_session_cache_set_cache_dir_is_none(self):
        # given dummy AWS session credentials
        aws_session_credentials = {
            "Credentials": {
                "AccessKeyId": "dummyAccessKeyId",
                "SecretAccessKey": "dummySecretAccessKey",
                "SessionToken": "dummySessionToken",
                "Expiration": datetime(2021, 9, 22, 9, 22, 24, tzinfo=timezone.utc),
            }
        }

        # when written to cache with None passed as cache_dir
        login._session_cache_set(None, "myprofile", aws_session_credentials)

        # then no error should happen

    def test_session_cache_get_cache_dir_is_none(self):
        # given None passed as cache_dir

        # when read from cache
        data = login._session_cache_get(None, "myprofile")

        # then the data should be None
        assert data is None

    def test_session_cache_set(self, tmp_path):
        # os.path.exists and os.path.join only supports PathLike objects since 3.6
        tmp_path = str(tmp_path)

        # given dummy AWS session credentials
        aws_session_credentials = {
            "Credentials": {
                "AccessKeyId": "dummyAccessKeyId",
                "SecretAccessKey": "dummySecretAccessKey",
                "SessionToken": "dummySessionToken",
                "Expiration": datetime(2021, 9, 22, 9, 22, 24, tzinfo=timezone.utc),
            }
        }

        # when written to cache
        login._session_cache_set(tmp_path, "myprofile", aws_session_credentials)

        # then the cache file should exist have valid json content
        expected_cache_file = os.path.join(tmp_path, "myprofile.json")
        assert os.path.exists(expected_cache_file)
        with open(expected_cache_file) as f:
            data = json.load(f)
        assert data["Credentials"]["AccessKeyId"] == "dummyAccessKeyId"
        assert data["Credentials"]["SecretAccessKey"] == "dummySecretAccessKey"
        assert data["Credentials"]["SessionToken"] == "dummySessionToken"
        assert data["Credentials"]["Expiration"] == "2021-09-22T09:22:24+0000"

    def test_session_cache_get_missing(self, tmp_path):
        # os.path.exists and os.path.join only supports PathLike objects since 3.6
        tmp_path = str(tmp_path)

        # given missing cached AWS session credentials

        # when read from cache
        data = login._session_cache_get(tmp_path, "myprofile")

        # then the data should be None
        assert data is None

    def test_session_cache_get_empty(self, tmp_path):
        # os.path.exists and os.path.join only supports PathLike objects since 3.6
        tmp_path = str(tmp_path)

        # given expired cached AWS session credentials
        cache_file = os.path.join(tmp_path, "myprofile.json")
        with open(cache_file, "w") as f:
            f.write("")

        # when read from cache
        data = login._session_cache_get(tmp_path, "myprofile")

        # then the data should be None
        assert data is None

    def test_session_cache_get_corrupt(self, tmp_path):
        # os.path.exists and os.path.join only supports PathLike objects since 3.6
        tmp_path = str(tmp_path)

        # given expired cached AWS session credentials
        cache_file = os.path.join(tmp_path, "myprofile.json")
        with open(cache_file, "w") as f:
            json.dump(
                {
                    "Credentials": {
                        "AccessKeyId": "dummyAccessKeyId",
                        "SecretAccessKey": "dummySecretAccessKey",
                        "SessionToken": "dummySessionToken",
                        "Expiration": "2021-01-02T01:02:03+0000",
                    }
                },
                f,
            )

        # when read from cache
        data = login._session_cache_get(tmp_path, "myprofile")

        # then the data should be the same
        assert data is None

    def test_session_cache_get_expired(self, tmp_path):
        # os.path.exists and os.path.join only supports PathLike objects since 3.6
        tmp_path = str(tmp_path)

        # given expired cached AWS session credentials
        cache_file = os.path.join(tmp_path, "myprofile.json")
        with open(cache_file, "w") as f:
            json.dump(
                {
                    "Credentials": {
                        "AccessKeyId": "dummyAccessKeyId",
                        "SecretAccessKey": "dummySecretAccessKey",
                        "SessionToken": "dummySessionToken",
                        "Expiration": "2021-01-02T01:02:03+0000",
                    }
                },
                f,
            )

        # when read from cache
        data = login._session_cache_get(tmp_path, "myprofile")

        # then the data should be the same
        assert data is None

    def test_session_cache_get_not_expired(self, tmp_path):
        # os.path.exists and os.path.join only supports PathLike objects since 3.6
        tmp_path = str(tmp_path)

        # given dummy not expired cached AWS session credentials
        expiration = datetime.now(tz=timezone.utc).replace(microsecond=0) + timedelta(
            hours=+1
        )
        cache_file = os.path.join(tmp_path, "myprofile.json")
        with open(cache_file, "w") as f:
            json.dump(
                {
                    "Credentials": {
                        "AccessKeyId": "dummyAccessKeyId",
                        "SecretAccessKey": "dummySecretAccessKey",
                        "SessionToken": "dummySessionToken",
                        "Expiration": expiration.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    }
                },
                f,
            )

        # when read from cache
        data = login._session_cache_get(tmp_path, "myprofile")

        # then the data should be the same
        assert data["Credentials"]["AccessKeyId"] == "dummyAccessKeyId"
        assert data["Credentials"]["SecretAccessKey"] == "dummySecretAccessKey"
        assert data["Credentials"]["SessionToken"] == "dummySessionToken"
        assert data["Credentials"]["Expiration"] == expiration

    def test_session_cache_set_then_get(self, tmp_path):
        # os.path.exists and os.path.join only supports PathLike objects since 3.6
        tmp_path = str(tmp_path)

        # given dummy AWS session credentials
        expiration = datetime.now(tz=timezone.utc).replace(microsecond=0) + timedelta(
            hours=+1
        )
        aws_session_credentials = {
            "Credentials": {
                "AccessKeyId": "dummyAccessKeyId",
                "SecretAccessKey": "dummySecretAccessKey",
                "SessionToken": "dummySessionToken",
                "Expiration": expiration,
            }
        }

        # when written to cache then read from cache
        login._session_cache_set(tmp_path, "myprofile", aws_session_credentials)
        data = login._session_cache_get(tmp_path, "myprofile")

        # then the data should be the same
        assert aws_session_credentials == data
