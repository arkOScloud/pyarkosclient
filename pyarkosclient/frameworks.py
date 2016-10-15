"""Includes API endpoints as Frameworks for calling."""
import aniso8601
import base64
import os
import time

from .errors import GeneralError


class Framework:
    """Class for a division of the API."""

    def __init__(self, connection):
        """Initialize."""
        self.conn = connection


class APIKeys(Framework):
    """Framework for API key authentication with Kraken."""

    def get(self):
        """
        Get a list of all API keys on the system.

        :returns: list of APIKey dicts
        """
        data = self.conn._get("/api_keys")
        return data.get("api_keys")

    def add(self, user, comment="pyarkOSclient"):
        """
        Create and save an API key.

        :param str user: name of user to create key for
        :returns: APIKey dict
        """
        key = {"user": user, "comment": comment}
        data = self.conn._post("/api_keys", {"api_key": key})
        return data.get("api_key")

    def revoke(self, id):
        """
        Revoke an existing API key.

        :param str id: ID of key to revoke
        """
        self.conn._delete("/api_keys/{0}".format(id))


class Applications(Framework):
    """Framework for managing arkOS applications."""

    def get(self, **kwargs):
        """
        Get application metadata.

        :param str id: (optional) if provided, filter by this app ID
        :returns: list of Application dicts
        """
        if kwargs.get("id"):
            data = self.conn._get("/apps/{0}".format(kwargs["id"]),
                                  params=kwargs)
        else:
            data = self.conn._get("/apps", params=kwargs)
        return data.get("app") or data.get("apps")

    def install(self, id):
        """
        Install an application.

        :param str id: ID of application to install
        :returns: tuple of Job object, Application dict
        """
        app = {"app": {"operation": "install"}}
        data = self.conn._put("/apps/{0}".format(id), app)
        return (data[0], data[1].get("app"))

    def upgrade(self, id):
        """
        Upgrade an application.

        :param str id: ID of application to upgrade
        :returns: tuple of Job object, Application dict
        """
        data = self.install(id)
        return (data[0], data[1].get("app"))

    def uninstall(self, id):
        """
        Uninstall an application.

        :param str id: ID of application to uninstall
        :returns: tuple of Job object, Application dict
        """
        app = {"app": {"operation": "uninstall"}}
        data = self.conn._put("/apps/{0}".format(id), app)
        return (data[0], data[1].get("app"))


class Backups(Framework):
    """Framework for managing arkOS backups."""

    def get(self, **kwargs):
        """
        Get backup metadata.

        :param str id: (optional) if provided, filter by this backup ID
        :param str time: (optional) if provided w/ID, filter by backup time
        :returns: list of Backup dicts
        """
        if kwargs.get("id") and kwargs.get("time"):
            full_id = kwargs["id"] + "/" + kwargs["time"]
            data = self.conn._get("/backups/{0}".format(full_id))
        elif kwargs.get("id"):
            data = self.conn._get("/backups/{0}".format(kwargs["id"]))
        else:
            data = self.conn._get("/backups")
        if data.get("backup"):
            t = data["backup"]["time"]
            data["backup"]["time"] = aniso8601.parse_datetime(t)
        elif data.get("backups"):
            for x in data.get("backups"):
                x["time"] = aniso8601.parse_datetime(x["time"])
        return data.get("backup") or data.get("backups")

    def get_types(self):
        """
        Get all types of backups possible.

        :returns: list of BackupType dicts
        """
        data = self.conn._get("/backups/types")
        return data.get("types")

    def create(self, id):
        """
        Create a backup.

        :param str id: ID of app or website to backup
        :returns: tuple of Job object, Backup dict
        """
        data = self.conn._post("/backups/{0}".format(id))
        return (data[0], data[1].get("backup"))

    def restore(self, id, time):
        """
        Restore a backup.

        :param str id: ID of backup to restore
        :param time id: timestamp of backup to restore
        :returns: tuple of Job object, Backup dict
        """
        data = self.conn._put("/backups/{0}".format(id)+"/"+time)
        return (data[0], data[1].get("backup"))

    def delete(self, id, time):
        """
        Delete a backup.

        :param str id: ID of backup to delete
        :param time id: timestamp of backup to delete
        """
        self.conn._delete("/backups/{0}".format(id)+"/"+time)


class Certificates(Framework):
    """Framework for managing arkOS SSL/TLS certificates."""

    def get(self, **kwargs):
        """
        Get certificate metadata.

        :param str id: (optional) if provided, filter by this cert ID
        :returns: list of Certificate dicts
        """
        if kwargs.get("id"):
            data = self.conn._get("/certificates/{0}".format(kwargs["id"]),
                                  params=kwargs)
        else:
            data = self.conn._get("/certificates", params=kwargs)
        if data.get("certificate"):
            ex = data["certificate"]["expiry"]
            data["certificate"]["expiry"] = aniso8601.parse_datetime(ex)
        elif data.get("certificates"):
            for x in data.get("certificates"):
                x["expiry"] = aniso8601.parse_datetime(x["expiry"])
        return data.get("certificate") or data.get("certificates")

    def get_authorities(self, **kwargs):
        """
        Get certificate authority metadata.

        :param str id: (optional) if provided, filter by this cert ID
        :returns: list of CertificateAuthority dicts
        """
        if kwargs.get("id"):
            data = self.conn._get("/authorities/{0}".format(kwargs["id"]),
                                  params=kwargs)
        else:
            data = self.conn._get("/authorities", params=kwargs)
        if data.get("authority"):
            ex = data["authority"]["expiry"]
            data["authority"]["expiry"] = aniso8601.parse_datetime(ex)
        elif data.get("authorities"):
            for x in data.get("authorities"):
                x["expiry"] = aniso8601.parse_datetime(x["expiry"])
        return data.get("authority") or data.get("authorities")

    def get_authority(self, **kwargs):
        """
        Get certificate authority metadata.

        :param str id: (optional) if provided, filter by this cert ID
        :returns: list of CertificateAuthority dicts
        """
        return self.get_authorities(**kwargs)

    def get_possible_assigns(self):
        """
        Get possible certificate assignments.

        :returns: list of Assign dicts
        """
        data = self.conn._get("/assignments")
        return data.get("assignments")

    def download_authority(self, id):
        """
        Download a certificate authority.

        :param str id: certificate authority ID
        :returns: CertificateAuthority as str
        """
        return self.conn._get("/authorities/{0}".format(id),
                              params={"download": True}, raw=True)

    def generate(
            self, name, domain, country, state=None, locale=None, email=None,
            keytype="RSA", keylength=2048):
        """
        Generate a self-signed certificate.

        :param str name: Name for new certificate
        :param str domain: Domain to use as certificate common name
        :param str country: Two-letter country code (e.g. 'US' or 'CA')
        :param str state: State or province
        :param str locale: City, town or locale
        :param str email: Contact email for user
        :param str keytype: Key type ("RSA" or "DSA")
        :param int keylength: Key length in bits
        :returns: tuple of Job object, Certificate dict
        """
        cert = {"id": name, "domain": domain, "country": country,
                "state": state, "locale": locale, "email": email,
                "keytype": keytype, "keylength": keylength}
        data = self.conn._post("/certificates", {"cert": cert})
        return (data[0], data[1].get("cert"))

    def upload(self, name, cert, key, chain=None):
        """
        Upload an SSL/TLS certificate to the server.

        :param str name: Name for new certificate
        :param cert: Path to cert, or open file-like object
        :param key: Path to key, or open file-like object
        :param chain: Path to chainfile, or open file-like object
        :returns: tuple of Job object, Certificate dict
        """
        if type(cert) == str:
            cert = open(cert, "r")
        if type(key) == str:
            key = open(key, "r")
        if type(chain) == str:
            cert = open(chain, "r")
        files = {"file[0]": cert, "file[1]": key, "file[2]": chain}
        data = self.conn._post("/certificates", data={"id": name}, files=files)
        return (data[0], data[1].get("cert"))

    def assign(self, id, atype=None, app_id=None, special_id=None,
               assign=None):
        """
        Assign a certificate to an app or website.

        :param str id: Name of certificate to assign
        :param str atype: Application type (e.g. "website" or "app")
        :param str app_id: Application or website ID
        :param str special_id: Special ID for application sub-type
        :param dict assign: Create your own assign object and pass in (opt)
        :returns: Certificate dict
        """
        if not atype and not assign:
            raise GeneralError("Must provide either assign data or its object")
        elif atype == "website" and not app_id:
            raise GeneralError("Must supply `app_id`")
        elif atype == "app" and (not app_id or not special_id):
            raise GeneralError("Must supply `app_id` and `special_id`")
        cert = self.get(id)
        assigns = cert["assigns"]
        if assign:
            assigns.append(assign)
        elif atype == "genesis":
            assigns.append({"type": "genesis"})
        elif atype == "website":
            assigns.append({"type": "website", "id": app_id})
        else:
            assigns.append({"type": "app", "aid": app_id, "sid": special_id})
        data = self.conn._put("/certificates/{0}".format(id),
                              {"cert": {"assigns": assigns}})
        return data.get("cert")

    def unassign(self, id, atype=None, app_id=None, special_id=None,
                 assign=None):
        """
        Remove a certificate from an app or website.

        :param str id: Name of certificate to remove
        :param str atype: Application type (e.g. "website" or "app")
        :param str app_id: Application or website ID
        :param str special_id: Special ID for application sub-type
        :param dict assign: Create your own assign object and pass in (opt)
        :returns: Certificate dict
        """
        if not atype and not assign:
            raise GeneralError("Must provide either assign data or its object")
        elif atype == "website" and not app_id:
            raise GeneralError("Must supply `app_id`")
        elif atype == "app" and (not app_id or not special_id):
            raise GeneralError("Must supply `app_id` and `special_id`")
        cert = self.get(id)
        assigns = cert["assigns"]
        if assign:
            assigns.remove(assign)
        elif atype == "genesis":
            assigns.remove({"type": "genesis"})
        elif atype == "website":
            assigns.remove({"type": "website", "id": app_id})
        else:
            assigns.remove({"type": "app", "aid": app_id, "sid": special_id})
        data = self.conn._put("/certificates/{0}".format(id),
                              {"cert": {"assigns": assigns}})
        return data.get("cert")

    def delete(self, id):
        """
        Delete a certificate.

        :param str id: Certificate name
        """
        self.conn._delete("/certificates/{0}".format(id))

    def delete_authority(self, id):
        """
        Delete a certificate authority.

        :param str id: Certificate authority name
        """
        self.conn._delete("/authorities/{0}".format(id))


class Config(Framework):
    """Framework for managing arkOS configuration data."""

    def get(self, section=None, key=None, default=None):
        """
        Get a configuration section or key, or the whole configuration.

        :param str section:
        """
        if not hasattr(self, "_config"):
            self.load()
        if section and key:
            if section in self._config and key in self._config[section] \
             and type(self._config[section][key]) in [list, dict]:
                return self._config[section].get(key)
            return self._config[section].get(key, default)
        elif section:
            return self._config.get(section, {})
        return self._config

    def set(self, section, key, value=None):
        if value is None:
            self._config[section] = key
        elif section in self._config:
            self._config[section][key] = value
        else:
            self._config[section] = {}
            self._config[section][key] = value
        self.save()

    def refresh(self):
        self.load()

    def save(self):
        self.conn._put("/config", {"config": self._config})

    def load(self):
        data = self.conn._get("/config")
        self._config = data.get("config")


class Databases(Framework):
    def get(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/databases/{0}".format(kwargs["id"]),
                                  params=kwargs)
        else:
            data = self.conn._get("/databases", params=kwargs)
        return data.get("database") or data.get("databases")

    def add(self, id, type_id):
        database = {"id": id, "type_id": type_id}
        data = self.conn._post("/databases", {"database": database})
        return data.get("database")

    def execute(self, id, cmd):
        data = self.conn._put("/databases/{0}".format(id),
                              {"database": {"execute": cmd}})
        return data.get("result")

    def dump(self, id):
        return self.conn._get("/databases/{0}".format(id),
                              params={"download": True}, raw=True)

    def delete(self, id):
        self.conn._delete("/databases/{0}".format(id))

    def get_users(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/database_users/{0}".format(kwargs["id"]),
                                  params=kwargs)
        else:
            data = self.conn._get("/database_users", params=kwargs)
        return data.get("database_user") or data.get("database_users")

    def get_user(self, **kwargs):
        return self.get_users(**kwargs)

    def add_user(self, id, type, passwd):
        dbuser = {"id": id, "type": type, "passwd": passwd}
        data = self.conn._post("/database_users", {"database_user": dbuser})
        return data.get("database_user")

    def user_chmod(self, id, op, db_id):
        dbuser = {"operation": op, "database": db_id}
        data = self.conn._put("/database_users/{0}".format(id),
                              {"database_user": dbuser})
        return data.get("database_user")

    def delete_user(self, id):
        self.conn._delete("/database_users/{0}".format(id))

    def get_types(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/database_types/{0}".format(kwargs["id"]),
                                  params=kwargs)
        else:
            data = self.conn._get("/database_types", params=kwargs)
        return data.get("database_types") or data.get("database_type")


class Files(Framework):
    def path_to_b64(self, path):
        # Convert a filesystem path to a safe base64-encoded string.
        path = path.replace("//", "/")
        return base64.b64encode(path, altchars="+-").replace("=", "*")

    def get(self, path, **kwargs):
        data = self.conn._get("/files/"+self.path_to_b64(path), params=kwargs)
        return data.get("file") or data.get("files")

    def get_shares(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/shared_files/{0}".format(kwargs["id"]),
                                  params=kwargs)
        else:
            data = self.conn._get("/shared_files", params=kwargs)
        if data.get("shared_file") and data["shared_file"]["expires_at"] \
           and data["shared_file"]["expires_at"] != 0:
            ex = data["shared_file"]["expires_at"]
            data["shared_file"]["expires_at"] = aniso8601.parse_datetime(ex)
        elif data.get("shared_files"):
            for x in data.get("shared_files"):
                if x["expires_at"] and x["expires_at"] != 0:
                    x["expires_at"] = aniso8601.parse_datetime(x["expires_at"])
        return data.get("shared_file") or data.get("shared_files")

    def get_share(self, **kwargs):
        return self.get_shares(**kwargs)

    def create_file(self, path):
        path, name = os.path.split(path)
        data = self.conn._post("/files/"+self.path_to_b64(path),
                               {"file": {"folder": False, "name": name}})
        return data.get("file")

    def create_folder(self, path):
        path, name = os.path.split(path)
        data = self.conn._post("/files/"+self.path_to_b64(path),
                               {"file": {"folder": True, "name": name}})
        return data.get("file")

    def upload(self, path, locfiles=[]):
        files_form = {}
        ffc = 0
        locfiles = [(open(x, "rb") if type(x) == str else x) for x in locfiles]
        for x in locfiles:
            files_form["file[{0}]".format(ffc)] = locfiles[ffc]
            ffc += 1
        data = self.conn._post("/files/"+self.path_to_b64(path),
                               files=files_form)
        return data.get("file")

    def download(self, path, save_to=None):
        shopt = {"path": path, "expires": 0}
        data = self.conn._post("/shares", {"share": shopt})
        data = data.get("share")
        data = self.conn._get("/shared/"+data["id"], no_api=True, raw=True)
        if save_to:
            with open(save_to, "wb") as f:
                f.write(data)
            return save_to
        return data

    def copy(self, from_path, to_path):
        fileopt = {"operation": "copy", "newdir": to_path}
        data = self.conn._put("/files/"+self.path_to_b64(from_path),
                              {"file": fileopt})
        return data.get("file")

    def rename(self, from_path, to_path):
        fileopt = {"operation": "rename", "name": to_path}
        data = self.conn._put("/files/"+self.path_to_b64(from_path),
                              {"file": fileopt})
        return data.get("file")

    def edit(self, path, data):
        fileopt = {"operation": "edit", "path": path, "data": data}
        data = self.conn._put("/files/"+self.path_to_b64(path),
                              {"file": fileopt})
        return data.get("file")

    def extract(self, path):
        data = self.conn._put("/files/"+self.path_to_b64(path),
                              {"file": {"operation": "extract"}})
        return data.get("file")

    def chmod(self, path, poct):
        fileopt = {"operation": "props", "perms": {"oct": poct}}
        data = self.conn._put("/files/"+self.path_to_b64(path),
                              {"file": fileopt})
        return data.get("file")

    def chown(self, path, user=None, group=None):
        if not user and not group:
            raise GeneralError("Must supply either user or group name to use")
        fileopt = {"operation": "props", "user": user, "group": group}
        data = self.conn._put("/files/"+self.path_to_b64(path),
                              {"file": fileopt})
        return data.get("file")

    def delete(self, path):
        self.conn._delete("/files/"+self.path_to_b64(path))

    def share(self, path, expires=None):
        if expires and type(expires) != int:
            expires = time.mktime(expires.timetuple()) * 1000
        fileopt = {"path": path, "expires": expires or 0}
        data = self.conn._post("/shares", {"share": fileopt})
        return data.get("share")

    def update_share(self, id, expires=None):
        if expires and type(expires) != int:
            expires = time.mktime(expires.timetuple()) * 1000
        shareopt = {"expires": True, "expires_at": expires or 0}
        data = self.conn._put("/shares/{0}".format(id), {"share": shareopt})
        return data.get("share")

    def remove_share(self, id):
        self.conn._delete("/shares/{0}".format(id))


class Filesystems(Framework):
    def get(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/system/filesystems/{0}"
                                  .format(kwargs["id"]), params=kwargs)
        else:
            data = self.conn._get("/system/filesystems", params=kwargs)
        return data.get("filesystem") or data.get("filesystems")

    def get_points(self):
        data = self.conn._get("/points")
        return data.get("points")

    def create_virtual(self, id, size, crypt=False, passwd=""):
        if crypt and not passwd:
            raise GeneralError("Must supply `passwd` for encryption")
        fsopt = {"id": id, "size": size, "crypt": crypt, "passwd": passwd}
        data = self.conn._post("/system/filesystems", {"filesystem": fsopt})
        return (data[0], data[1].get("filesystem"))

    def mount(self, id, passwd=""):
        fsopt = {"operation": "mount", "passwd": passwd}
        data = self.conn._put("/system/filesystems/{0}".format(id),
                              {"filesystem": fsopt})
        return data.get("filesystem")

    def umount(self, id):
        data = self.conn._put("/system/filesystems/{0}".format(id),
                              {"filesystem": {"operation": "umount"}})
        return data.get("filesystem")

    def enable(self, id):
        data = self.conn._put("/system/filesystems/{0}".format(id),
                              {"filesystem": {"operation": "enable"}})
        return data.get("filesystem")

    def disable(self, id):
        data = self.conn._put("/system/filesystems/{0}".format(id),
                              {"filesystem": {"operation": "disable"}})
        return data.get("filesystem")

    def delete(self, id):
        self.conn._delete("/system/filesystems/{0}".format(id))


class Networks(Framework):
    def get(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/system/networks/{0}".format(kwargs["id"]),
                                  params=kwargs)
        else:
            data = self.conn._get("/system/networks", params=kwargs)
        return data.get("network") or data.get("networks")

    def get_interfaces(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/system/netifaces/{0}".format(kwargs["id"]),
                                  params=kwargs)
        else:
            data = self.conn._get("/system/netifaces", params=kwargs)
        return data.get("netiface") or data.get("netifaces")

    def get_interface(self, **kwargs):
        return self.get_interfaces(**kwargs)

    def add(self, id, config):
        data = self.conn._post("/system/networks", {"network":
                               {"id": id, "config": config}})
        return data.get("network")

    def connect(self, id):
        data = self.conn._put("/system/networks/{0}".format(id),
                              {"network": {"operation": "connect"}})
        return data.get("network")

    def disconnect(self, id):
        data = self.conn._put("/system/networks/{0}".format(id),
                              {"network": {"operation": "disconnect"}})
        return data.get("network")

    def enable(self, id):
        data = self.conn._put("/system/networks/{0}".format(id),
                              {"network": {"operation": "enable"}})
        return data.get("network")

    def disable(self, id):
        data = self.conn._put("/system/networks/{0}".format(id),
                              {"network": {"operation": "disable"}})
        return data.get("network")

    def delete(self, id):
        self.conn._delete("/system/networks/{0}".format(id))


class Packages(Framework):
    def get(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/system/packages/{0}".format(kwargs["id"]),
                                  params=kwargs)
        else:
            data = self.conn._get("/system/packages", params=kwargs)
        return data.get("package") or data.get("packages")

    def install(self, ids):
        if type(ids) not in [tuple, list]:
            ids = [ids]
        pkgs = [{"id": x, "operation": "install"} for x in ids]
        data = self.conn._post("/system/packages",
                               {"packages": pkgs})
        return data[0]

    def remove(self, ids):
        if type(ids) not in [tuple, list]:
            ids = [ids]
        pkgs = [{"id": x, "operation": "remove"} for x in ids]
        data = self.conn._post("/system/packages", {"packages": pkgs})
        return data[0]


class Roles(Framework):
    def get_users(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/system/users/{0}".format(kwargs["id"]),
                                  params=kwargs)
        else:
            data = self.conn._get("/system/users", params=kwargs)
        return data.get("user") or data.get("users")

    def get_user(self, **kwargs):
        return self.get_users(**kwargs)

    def add_user(self, name, passwd, domain, first_name, last_name="",
                 admin=False, sudo=False):
        user = {"name": name, "domain": domain, "first_name": first_name,
                "last_name": last_name, "admin": admin, "sudo": sudo,
                "passwd": passwd}
        data = self.conn._post("/system/users", {"user": user})
        return data.get("user")

    def edit_user(
            self, id, domain="", first_name="", last_name="", passwd="",
            admin=None, sudo=None, mail_addresses=[]):
        if not any([domain, first_name, last_name, passwd, admin is not None,
                    sudo is not None, mail_addresses]):
            raise GeneralError("Must supply items to edit")
        data = self.conn._get("/system/users/{0}".format(id))
        data = data.get("user")
        first_name = first_name or data["first_name"]
        last_name = last_name or data["last_name"]
        passwd = passwd or ""
        admin = admin or data["admin"]
        sudo = sudo or data["sudo"]
        mail_addresses = mail_addresses or data["mail_addresses"]
        user = {"domain": domain, "first_name": first_name,
                "last_name": last_name, "admin": admin, "sudo": sudo,
                "passwd": passwd, "mail_addresses": mail_addresses}
        data = self.conn._put("/system/users/{0}".format(id), {"user": user})
        return data.get("user")

    def delete_user(self, id):
        self.conn._delete("/system/users/{0}".format(id))

    def get_groups(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/system/groups/{0}".format(kwargs["id"]),
                                  params=kwargs)
        else:
            data = self.conn._get("/system/groups", params=kwargs)
        return data.get("group") or data.get("groups")

    def get_group(self, **kwargs):
        return self.get_groups(**kwargs)

    def add_group(self, name, users=[]):
        groupopt = {"name": name, "users": users}
        data = self.conn._post("/system/groups", {"group": groupopt})
        return data.get("group")

    def edit_group(self, id, users=[]):
        data = self.conn._put("/system/groups/{0}".format(id),
                              {"group": {"users": users}})
        return data.get("group")

    def delete_group(self, id):
        self.conn._delete("/system/groups/{0}".format(id))

    def get_domains(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/system/domains/{0}".format(kwargs["id"]),
                                  params=kwargs)
        else:
            data = self.conn._get("/system/domains", params=kwargs)
        return data.get("domain") or data.get("domains")

    def get_domain(self, **kwargs):
        return self.get_domains(**kwargs)

    def add_domain(self, id):
        data = self.conn._post("/system/domains", {"domain": {"id": id}})
        return data.get("domain")

    def delete_domain(self, id):
        self.conn._delete("/system/domains/{0}".format(id))


class Security(Framework):
    def get_policies(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/system/policies/{0}".format(kwargs["id"]),
                                  params=kwargs)
        else:
            data = self.conn._get("/system/policies", params=kwargs)
        return data.get("policy") or data.get("policies")

    def get_policy(self, **kwargs):
        return self.get_policies(**kwargs)

    def update_policy(self, id, policy):
        if type(policy) == str:
            if policy == "allow":
                policy = 2
            elif policy == "local":
                policy = 1
            else:
                policy = 0
        data = self.conn._put("/system/policies/{0}".format(id),
                              {"policy": {"policy": policy}})
        return data.get("policy")


class Services(Framework):
    def get(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/system/services/{0}".format(kwargs["id"]),
                                  params=kwargs)
        else:
            data = self.conn._get("/system/services", params=kwargs)
        return data.get("service") or data.get("services")

    def create(self, id, config):
        data = self.conn._post("/system/services",
                               {"service": {"id": id, "cfg": config}})
        return data.get("service")

    def start(self, id):
        data = self.conn._put("/system/services/{0}".format(id),
                              {"service": {"operation": "start"}})
        return data.get("service")

    def stop(self, id):
        data = self.conn._put("/system/services/{0}".format(id),
                              {"service": {"operation": "stop"}})
        return data.get("service")

    def restart(self, id):
        data = self.conn._put("/system/services/{0}".format(id),
                              {"service": {"operation": "restart"}})
        return data.get("service")

    def real_restart(self, id):
        data = self.conn._put("/system/services/{0}".format(id),
                              {"service": {"operation": "real_restart"}})
        return data.get("service")

    def enable(self, id):
        data = self.conn._put("/system/services/{0}".format(id),
                              {"service": {"operation": "enable"}})
        return data.get("service")

    def disable(self, id):
        data = self.conn._put("/system/services/{0}".format(id),
                              {"service": {"operation": "disable"}})
        return data.get("service")

    def delete(self, id):
        self.conn._delete("/system/services/{0}".format(id))


class System(Framework):
    def get_time(self, data=None):
        if not data:
            data = self.conn._get("/config/datetime")
        data = data.get("datetime")
        return {"datetime": aniso8601.parse_datetime(data["datetime"]),
                "offset": data["offset"]}

    def set_time(self):
        data = self.conn._put("/config/datetime")
        return self.get_time(data)

    def get_stats(self):
        data = self.conn._get("/system/stats/all")
        return data

    def get_ssh_keys(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/system/ssh_keys/{0}".format(kwargs["id"]),
                                  params=kwargs)
        else:
            data = self.conn._get("/system/ssh_keys", params=kwargs)
        return data.get("ssh_key") or data.get("ssh_keys")

    def get_ssh_key(self, **kwargs):
        return self.get_ssl_keys(**kwargs)

    def add_ssh_key(self, user, key=None, path=None):
        if not key and not path:
            excmsg = "Must supply either public key (str) or its path on disk"
            raise GeneralError(excmsg)
        if path:
            with open(path, "r") as f:
                key = f.read().rstrip("\n")
        data = self.conn._post("/system/ssh_keys",
                               {"ssh_key": {"user": user, "key": key}})
        return data.get("ssh_key")

    def delete_ssh_key(self, id):
        self.conn._delete("/system/ssh_keys/{0}".format(id))

    def shutdown(self):
        self.conn._post("/system/shutdown")

    def reboot(self):
        self.conn._post("/system/reboot")


class Updates(Framework):
    def get(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/updates/{0}".format(kwargs["id"]),
                                  params=kwargs)
        else:
            data = self.conn._get("/updates", params=kwargs)
        return data.get("update") or data.get("updates")

    def apply(self):
        data = self.conn._post("/updates")
        return data[0]


class Websites(Framework):
    def get(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/websites/{0}".format(kwargs["id"]),
                                  params=kwargs)
        else:
            data = self.conn._get("/websites", params=kwargs)
        return data.get("website") or data.get("websites")

    def create(self, id, site_type, addr, port, extra_data={}):
        webobj = {"id": id, "site_type": site_type, "domain": addr,
                  "port": port, "extra_data": extra_data}
        data = self.conn._post("/websites", {"website": webobj})
        return (data[0], data[1].get("website"))

    def edit(self, id, new_name="", addr=None, port=None):
        if not new_name and not addr and not port:
            raise GeneralError("Must supply items to edit")
        data = self.conn._get("/websites/{0}".format(id))
        data = data.get("website")
        addr = addr or data["domain"]
        port = port or data["port"]
        webobj = {"domain": addr, "port": port, "new_name": new_name}
        data = self.conn._put("/websites/{0}".format(id), {"website": webobj})
        return data.get("website")

    def enable(self, id):
        data = self.conn._put("/websites/{0}".format(id),
                              {"website": {"operation": "enable"}})
        return data.get("website")

    def disable(self, id):
        data = self.conn._put("/websites/{0}".format(id),
                              {"website": {"operation": "disable"}})
        return data.get("website")

    def enable_ssl(self, id, cert):
        webobj = {"operation": "enable_ssl", "cert": cert}
        data = self.conn._put("/websites/{0}".format(id),
                              {"website": webobj})
        return data.get("website")

    def disable_ssl(self, id):
        data = self.conn._put("/websites/{0}".format(id),
                              {"website": {"operation": "disable_ssl"}})
        return data.get("website")

    def update(self, id):
        data = self.conn._put("/websites/{0}".format(id),
                              {"website": {"operation": "update"}})
        return data.get("website")

    def action(self, id, action):
        self.conn._post("/websites/actions/{0}".format(id)+"/"+action)

    def delete(self, id):
        data = self.conn._delete("/websites/{0}".format(id))
        return data
