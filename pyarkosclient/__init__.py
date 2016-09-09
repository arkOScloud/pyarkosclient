import requests

from .frameworks import *
from .errors import GeneralError, NotFoundError, AuthenticationError, ServerError


class arkOS:
    def __init__(self, host="http://127.0.0.1:8765", username="", password="", api_key=""):
        self.host = host
        if username and password:
            try:
                r = requests.post(host+"/api/token", json={"username": username, "password": password})
                self._process_http_status(r)
                self.token = r.json().get('token')
                self.api_key = None
            except requests.exceptions.ConnectionError:
                raise GeneralError("The server could not be reached.")
        elif api_key:
            try:
                r = requests.get(host+"/api/ping", headers={"X-API-Key": api_key})
                self._process_http_status(r)
                self.api_key = api_key
                self.token = None
            except requests.exceptions.ConnectionError:
                raise GeneralError("The server could not be reached.")
        elif not username or not password or not api_key:
            raise GeneralError("Username/password or API key required")
        self._register_frameworks()

    def refresh_token(self):
        if self.token:
            try:
                r = requests.post(self.host+"/api/token/refresh", json={"token": self.token})
                self._process_http_status(r)
                self.token = r.json().get('token')
            except requests.exceptions.ConnectionError:
                raise GeneralError("The server could not be reached.")

    def _register_frameworks(self):
        self.apikeys = APIKeys(self)
        self.applications = Applications(self)
        self.backups = Backups(self)
        self.certificates = Certificates(self)
        self.config = Config(self)
        self.databases = Databases(self)
        self.files = Files(self)
        self.filesystems = Filesystems(self)
        self.networks = Networks(self)
        self.packages = Packages(self)
        self.roles = Roles(self)
        self.security = Security(self)
        self.services = Services(self)
        self.system = System(self)
        self.updates = Updates(self)
        self.websites = Websites(self)

    def _process_http_status(self, r):
        if r.status_code in [200, 201, 202, 204]:
            return
        elif r.status_code == 400:
            raise GeneralError("Bad Request")
        elif r.status_code == 401:
            raise AuthenticationError()
        elif r.status_code == 404:
            raise NotFoundError()
        elif r.status_code == 422:
            raise Exception(r.json().get("message"))
        elif str(r.status_code).startswith("5"):
            try:
                data = r.json()
            except:
                data = {}
            raise ServerError(r.status_code, data)

    def _get(self, endpoint, params=None, raw=False, no_api=False, headers={}):
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        else:
            headers["Authorization"] = "Bearer " + self.token
        try:
            r = requests.get(self.host+("/api" if not no_api else "")+endpoint, headers=headers, params=params)
        except requests.exceptions.ConnectionError:
            raise GeneralError("The server could not be reached.")
        self._process_http_status(r)
        return r.json() if not raw else r.content

    def _post(self, endpoint, json=None, data=None, files=None, raw=False, headers={}):
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        else:
            headers["Authorization"] = "Bearer " + self.token
        try:
            if data or files:
                r = requests.post(self.host+"/api"+endpoint, headers=headers, data=data, files=files)
            elif json:
                r = requests.post(self.host+"/api"+endpoint, headers=headers, json=json)
            else:
                r = requests.post(self.host+"/api"+endpoint, headers=headers)
        except requests.exceptions.ConnectionError:
            raise GeneralError("The server could not be reached.")
        self._process_http_status(r)
        if r.status_code == 202 and r.headers.get("Location"):
            job = Job(self.host, r.headers.get("Location").split("/")[-1])
            data = {}
            try:
                data = r.json()
            except:
                pass
            return (job, data)
        return r.json() if not raw else r.content

    def _put(self, endpoint, json=None, raw=False, headers={}):
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        else:
            headers["Authorization"] = "Bearer " + self.token
        try:
            r = requests.put(self.host+"/api"+endpoint, headers=headers, json=json)
        except requests.exceptions.ConnectionError:
            raise GeneralError("The server could not be reached.")
        self._process_http_status(r)
        if r.status_code == 202 and r.headers.get("Location"):
            job = Job(self.host, r.headers.get("Location").split("/")[-1])
            return (job, r.json())
        return r.json() if not raw else r.content

    def _patch(self, endpoint, json=None, raw=False, headers={}):
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        else:
            headers["Authorization"] = "Bearer " + self.token
        try:
            r = requests.patch(self.host+"/api"+endpoint, headers=headers, json=json)
        except requests.exceptions.ConnectionError:
            raise GeneralError("The server could not be reached.")
        self._process_http_status(r)
        if r.status_code == 202 and r.headers.get("Location"):
            job = Job(self.host, r.headers.get("Location").split("/")[-1])
            return (job, r.json())
        return r.json() if not raw else r.content

    def _delete(self, endpoint, headers={}):
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        else:
            headers["Authorization"] = "Bearer " + self.token
        try:
            r = requests.delete(self.host+"/api"+endpoint, headers=headers)
        except requests.exceptions.ConnectionError:
            raise GeneralError("The server could not be reached.")
        self._process_http_status(r)
        if r.status_code == 202 and r.headers.get("Location"):
            job = Job(self.host, r.headers.get("Location").split("/")[-1])
            return job
        return r


class Job(object):
    def __init__(self, host, id, status="running"):
        self.host = host
        self.id = id
        self.status = status
        self.message = None

    def _set_status(self, status):
        if status == 200:
            self.status = "running"
        elif status == 400:
            self.status = "error_request"
        elif status == 500:
            self.status = "error_server"
        else:
            self.status = "success"

    def check(self):
        r = requests.get(self.host+"/api/jobs/"+self.id)
        try:
            self.message = r.json()
        except:
            pass
        self._set_status(r.status_code)
        return self.status

    def __repr__(self):
        return "<Job {}>".format(self.id)
