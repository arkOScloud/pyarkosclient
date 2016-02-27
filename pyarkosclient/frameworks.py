import aniso8601
import base64
import os
import time

from .errors import GeneralError


class Framework:
    def __init__(self, connection):
        self.conn = connection


class APIKeys(Framework):
    def get(self):
        data = self.conn._get("/api_keys")
        return data.get("api_keys")

    def add(self, user, comment="pyarkOSclient"):
        data = self.conn._post("/api_keys", {"api_key": {"user": user, "comment": comment}})
        return data.get("api_key")

    def revoke(self, id):
        self.conn._delete("/api_keys/{}".format(id))


class Applications(Framework):
    def get(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/apps/{}".format(kwargs["id"]), params=kwargs)
        else:
            data = self.conn._get("/apps", params=kwargs)
        return data.get("app") or data.get("apps")

    def install(self, id):
        data = self.conn._put("/apps/{}".format(id), {"app": {"operation": "install"}})
        return (data[0], data[1].get("app"))

    def upgrade(self, id):
        data = self.install(id)
        return (data[0], data[1].get("app"))

    def uninstall(self, id):
        data = self.conn._put("/apps/{}".format(id), {"app": {"operation": "uninstall"}})
        return (data[0], data[1].get("app"))


class Backups(Framework):
    def get(self, **kwargs):
        if kwargs.get("id") and kwargs.get("time"):
            data = self.conn._get("/backups/{}".format(kwargs["id"])+"/"+kwargs["time"])
        elif kwargs.get("id"):
            data = self.conn._get("/backups/{}".format(kwargs["id"]))
        else:
            data = self.conn._get("/backups")
        if data.get("backup"):
            data["backup"]["time"] = aniso8601.parse_datetime(data["backup"]["time"])
        elif data.get("backups"):
            for x in data.get("backups"):
                x["time"] = aniso8601.parse_datetime(x["time"])
        return data.get("backup") or data.get("backups")

    def get_types(self):
        data = self.conn._get("/backups/types")
        return data.get("types")

    def create(self, id):
        data = self.conn._post("/backups/{}".format(id))
        return (data[0], data[1].get("backup"))

    def restore(self, id, time):
        data = self.conn._put("/backups/{}".format(id)+"/"+time)
        return (data[0], data[1].get("backup"))

    def delete(self, id, time):
        self.conn._delete("/backups/{}".format(id)+"/"+time)


class Certificates(Framework):
    def get(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/certs/{}".format(kwargs["id"]), params=kwargs)
        else:
            data = self.conn._get("/certs", params=kwargs)
        if data.get("cert"):
            data["cert"]["expiry"] = aniso8601.parse_datetime(data["cert"]["expiry"])
        elif data.get("certs"):
            for x in data.get("certs"):
                x["expiry"] = aniso8601.parse_datetime(x["expiry"])
        return data.get("cert") or data.get("certs")

    def get_authorities(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/certauths/{}".format(kwargs["id"]), params=kwargs)
        else:
            data = self.conn._get("/certauths", params=kwargs)
        if data.get("certauth"):
            data["certauth"]["expiry"] = aniso8601.parse_datetime(data["cert"]["expiry"])
        elif data.get("certauths"):
            for x in data.get("certauths"):
                x["expiry"] = aniso8601.parse_datetime(x["expiry"])
        return data.get("certauth") or data.get("certauths")

    def get_authority(self, **kwargs):
        return self.get_authorities(**kwargs)

    def get_possible_assigns(self):
        data = self.conn._get("/certassigns")
        return data.get("certassigns")

    def download_authority(self, id):
        return self.conn._get("/certauths/{}".format(id), params={"download": True}, raw=True)

    def generate(
            self, name, domain, country, state=None, locale=None, email=None,
            keytype="RSA", keylength=2048):
        data = self.conn._post("/certs", {"cert": {"id": name, "domain": domain,
            "country": country, "state": state, "locale": locale, "email": email,
            "keytype": keytype, "keylength": keylength}})
        return (data[0], data[1].get("cert"))

    def upload(self, name, cert, key, chain=None):
        if type(cert) == str:
            cert = open(cert, "r")
        if type(key) == str:
            key = open(key, "r")
        if type(chain) == str:
            cert = open(chain, "r")
        data = self.conn._post("/certs", data={"id": name}, files={"file[0]": cert,
            "file[1]": key, "file[2]": chain})
        return (data[0], data[1].get("cert"))

    def assign(self, id, atype=None, app_id=None, special_id=None, assign=None):
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
        data = self.conn._put("/certs/{}".format(id), {"cert": {"assigns": assigns}})
        return data.get("cert")

    def unassign(self, id, atype=None, app_id=None, special_id=None, assign=None):
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
        data = self.conn._put("/certs/{}".format(id), {"cert": {"assigns": assigns}})
        return data.get("cert")

    def delete(self, id):
        self.conn._delete("/certs/{}".format(id))

    def delete_authority(self, id):
        self.conn._delete("/certauths/{}".format(id))


class Config(Framework):
    def get(self, section=None, key=None, default=None):
        if not hasattr(self, "_config"):
            self.load()
        if section and key:
            if self._config.has_key(section) and self._config[section].has_key(key) \
            and type(self._config[section][key]) in [list, dict]:
                return self._config[section].get(key)
            return self._config[section].get(key, default)
        elif section:
            return self._config.get(section, {})
        return self._config

    def set(self, section, key, value=None):
        if value == None:
            self._config[section] = key
        elif self._config.has_key(section):
            self._config[section][key] = value
        else:
            self._config[section] = {}
            self._config[section][key] = value
        self.save()

    def refresh(self):
        self.load()

    def save(self):
        data = self.conn._put("/config", {"config": self._config})

    def load(self):
        data = self.conn._get("/config")
        self._config = data.get("config")


class Databases(Framework):
    def get(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/databases/{}".format(kwargs["id"]), params=kwargs)
        else:
            data = self.conn._get("/databases", params=kwargs)
        return data.get("database") or data.get("databases")

    def add(self, id, type_id):
        data = self.conn._post("/databases", {"database": {"id": id, "type_id": type_id}})
        return data.get("database")

    def execute(self, id, cmd):
        data = self.conn._put("/databases/{}".format(id), {"database": {"execute": cmd}})
        return data.get("result")

    def dump(self, id):
        return self.conn._get("/databases/{}".format(id), params={"download": True}, raw=True)

    def delete(self, id):
        self.conn._delete("/databases/{}".format(id))

    def get_users(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/database_users/{}".format(kwargs["id"]), params=kwargs)
        else:
            data = self.conn._get("/database_users", params=kwargs)
        return data.get("database_user") or data.get("database_users")

    def get_user(self, **kwargs):
        return self.get_users(**kwargs)

    def add_user(self, id, type, passwd):
        data = self.conn._post("/database_users", {"database_user": {"id": id, "type": type, "passwd": passwd}})
        return data.get("database_user")

    def user_chmod(self, id, op, db_id):
        data = self.conn._put("/database_users/{}".format(id), {"database_user": {"operation": op, "database": db_id}})
        return data.get("database_user")

    def delete_user(self, id):
        self.conn._delete("/database_users/{}".format(id))

    def get_types(self, **kwargs):
        data = self.conn._get("/database_types", params=kwargs)
        return data.get("database_types")


class Files(Framework):
    def path_to_b64(self, path):
        # Convert a filesystem path to a safe base64-encoded string.
        path = path.replace("//","/")
        return base64.b64encode(path, altchars="+-").replace("=", "*")

    def get(self, path, **kwargs):
        data = self.conn._get("/files/"+self.path_to_b64(path), params=kwargs)
        return data.get("file") or data.get("files")

    def get_shares(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/shares/{}".format(kwargs["id"]), params=kwargs)
        else:
            data = self.conn._get("/shares", params=kwargs)
        if data.get("share") and data["share"]["expires_at"] and data["share"]["expires_at"] != 0:
            data["share"]["expires_at"] = aniso8601.parse_datetime(data["share"]["expires_at"])
        elif data.get("shares"):
            for x in data.get("shares"):
                if x["expires_at"] and x["expires_at"] != 0:
                    x["expires_at"] = aniso8601.parse_datetime(x["expires_at"])
        return data.get("share") or data.get("shares")

    def get_share(self, **kwargs):
        return self.get_shares(**kwargs)

    def create_file(self, path):
        path, name = os.path.split(path)
        data = self.conn._post("/files/"+self.path_to_b64(path), {"file": {"folder": False, "name": name}})
        return data.get("file")

    def create_folder(self, path):
        path, name = os.path.split(path)
        data = self.conn._post("/files/"+self.path_to_b64(path), {"file": {"folder": True, "name": name}})
        return data.get("file")

    def upload(self, path, localfiles=[]):
        files_form = {}
        ffc = 0
        localfiles = map(lambda x: open(x, "rb") if type(x) == str else x, localfiles)
        for x in localfiles:
            files_form["file[{}]".format(ffc)] = localfiles[ffc]
            ffc += 1
        data = self.conn._post("/files/"+self.path_to_b64(path), files=files_form)
        return data.get("file")

    def download(self, path, save_to=None):
        data = self.conn._post("/shares", {"share": {"path": path, "expires": 0}})
        data = data.get("share")
        data = self.conn._get("/shared/"+data["id"], no_api=True, raw=True)
        if save_to:
            with open(save_to, "wb") as f:
                f.write(data)
            return save_to
        return data

    def copy(self, from_path, to_path):
        data = self.conn._put("/files/"+self.path_to_b64(from_path),
            {"file": {"operation": "copy", "newdir": to_path}})
        return data.get("file")

    def rename(self, from_path, to_path):
        data = self.conn._put("/files/"+self.path_to_b64(from_path),
            {"file": {"operation": "rename", "name": to_path}})
        return data.get("file")

    def edit(self, path, data):
        data = self.conn._put("/files/"+self.path_to_b64(path),
            {"file": {"operation": "edit", "path": path, "data": data}})
        return data.get("file")

    def extract(self, path):
        data = self.conn._put("/files/"+self.path_to_b64(path), {"file": {"operation": "extract"}})
        return data.get("file")

    def chmod(self, path, poct):
        data = self.conn._put("/files/"+self.path_to_b64(path),
            {"file": {"operation": "props", "perms": {"oct": poct}}})
        return data.get("file")

    def chown(self, path, user=None, group=None):
        if not user and not group:
            raise GeneralError("Must supply either `user` or `group` name to use")
        data = self.conn._put("/files/"+self.path_to_b64(path),
            {"file": {"operation": "props", "user": user, "group": group}})
        return data.get("file")

    def delete(self, path):
        self.conn._delete("/files/"+self.path_to_b64(path))

    def share(self, path, expires=None):
        if expires and type(expires) != int:
            expires = time.mktime(expires.timetuple()) * 1000
        data = self.conn._post("/shares", {"share": {"path": path, "expires": expires or 0}})
        return data.get("share")

    def update_share(self, id, expires=None):
        if expires and type(expires) != int:
            expires = time.mktime(expires.timetuple()) * 1000
        data = self.conn._put("/shares/{}".format(id), {"share": {"expires": True,
                "expires_at": expires or 0}})
        return data.get("share")

    def remove_share(self, id):
        self.conn._delete("/shares/{}".format(id))


class Filesystems(Framework):
    def get(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/system/filesystems/{}".format(kwargs["id"]), params=kwargs)
        else:
            data = self.conn._get("/system/filesystems", params=kwargs)
        return data.get("filesystem") or data.get("filesystems")

    def get_points(self):
        data = self.conn._get("/points")
        return data.get("points")

    def create_virtual(self, id, size, crypt=False, passwd=""):
        if crypt and not passwd:
            raise GeneralError("Must supply `passwd` for encryption")
        data = self.conn._post("/system/filesystems", {"filesystem": {"id": id, "size": size,
            "crypt": crypt, "passwd": passwd}})
        return (data[0], data[1].get("filesystem"))

    def mount(self, id, passwd=""):
        data = self.conn._put("/system/filesystems/{}".format(id), {"filesystem": {"operation": "mount", "passwd": passwd}})
        return data.get("filesystem")

    def umount(self, id):
        data = self.conn._put("/system/filesystems/{}".format(id), {"filesystem": {"operation": "umount"}})
        return data.get("filesystem")

    def enable(self, id):
        data = self.conn._put("/system/filesystems/{}".format(id), {"filesystem": {"operation": "enable"}})
        return data.get("filesystem")

    def disable(self, id):
        data = self.conn._put("/system/filesystems/{}".format(id), {"filesystem": {"operation": "disable"}})
        return data.get("filesystem")

    def delete(self, id):
        self.conn._delete("/system/filesystems/{}".format(id))


class Networks(Framework):
    def get(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/system/networks/{}".format(kwargs["id"]), params=kwargs)
        else:
            data = self.conn._get("/system/networks", params=kwargs)
        return data.get("network") or data.get("networks")

    def get_interfaces(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/system/netifaces/{}".format(kwargs["id"]), params=kwargs)
        else:
            data = self.conn._get("/system/netifaces", params=kwargs)
        return data.get("netiface") or data.get("netifaces")

    def get_interface(self, **kwargs):
        return self.get_interfaces(**kwargs)

    def add(self, id, config):
        data = self.conn._post("/system/networks", {"network": {"id": id, "config": config}})
        return data.get("network")

    def connect(self, id):
        data = self.conn._put("/system/networks/{}".format(id), {"network": {"operation": "connect"}})
        return data.get("network")

    def disconnect(self, id):
        data = self.conn._put("/system/networks/{}".format(id), {"network": {"operation": "disconnect"}})
        return data.get("network")

    def enable(self, id):
        data = self.conn._put("/system/networks/{}".format(id), {"network": {"operation": "enable"}})
        return data.get("network")

    def disable(self, id):
        data = self.conn._put("/system/networks/{}".format(id), {"network": {"operation": "disable"}})
        return data.get("network")

    def delete(self, id):
        self.conn._delete("/system/networks/{}".format(id))


class Packages(Framework):
    def get(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/system/packages/{}".format(kwargs["id"]), params=kwargs)
        else:
            data = self.conn._get("/system/packages", params=kwargs)
        return data.get("package") or data.get("packages")

    def install(self, ids):
        if type(ids) not in [tuple, list]:
            ids = [ids]
        data = self.conn._post("/system/packages", {"packages": [{"id": x, "operation": "install"} for x in ids]})
        return data[0]

    def remove(self, ids):
        if type(ids) not in [tuple, list]:
            ids = [ids]
        data = self.conn._post("/system/packages", {"packages": [{"id": x, "operation": "remove"} for x in ids]})
        return data[0]


class Roles(Framework):
    def get_users(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/system/users/{}".format(kwargs["id"]), params=kwargs)
        else:
            data = self.conn._get("/system/users", params=kwargs)
        return data.get("user") or data.get("users")

    def get_user(self, **kwargs):
        return self.get_users(**kwargs)

    def add_user(self, name, passwd, domain, first_name, last_name="", admin=False, sudo=False):
        data = self.conn._post("/system/users", {"user": {"name": name, "domain": domain,
            "first_name": first_name, "last_name": last_name, "admin": admin, "sudo": sudo, "passwd": passwd}})
        return data.get("user")

    def edit_user(
            self, id, domain="", first_name="", last_name="", passwd="", admin=None, sudo=None,
            mail_addresses=[]):
        if not any([domain, first_name, last_name, passwd, admin != None, sudo != None, mail_addresses]):
            raise GeneralError("Must supply items to edit")
        data = self.conn._get("/system/users/{}".format(id))
        data = data.get("user")
        first_name = first_name or data["first_name"]
        last_name = last_name or data["last_name"]
        passwd = passwd or ""
        admin = admin or data["admin"]
        sudo = sudo or data["sudo"]
        mail_addresses = mail_addresses or data["mail_addresses"]
        data = self.conn._put("/system/users/{}".format(id), {"user": {"domain": domain, "first_name": first_name,
            "last_name": last_name, "admin": admin, "sudo": sudo, "passwd": passwd,
            "mail_addresses": mail_addresses}})
        return data.get("user")

    def delete_user(self, id):
        self.conn._delete("/system/users/{}".format(id))

    def get_groups(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/system/groups/{}".format(kwargs["id"]), params=kwargs)
        else:
            data = self.conn._get("/system/groups", params=kwargs)
        return data.get("group") or data.get("groups")

    def get_group(self, **kwargs):
        return self.get_groups(**kwargs)

    def add_group(self, name, users=[]):
        data = self.conn._post("/system/groups", {"group": {"name": name, "users": users}})
        return data.get("group")

    def edit_group(self, id, users=[]):
        data = self.conn._put("/system/groups/{}".format(id), {"group": {"users": users}})
        return data.get("group")

    def delete_group(self, id):
        self.conn._delete("/system/groups/{}".format(id))

    def get_domains(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/system/domains/{}".format(kwargs["id"]), params=kwargs)
        else:
            data = self.conn._get("/system/domains", params=kwargs)
        return data.get("domain") or data.get("domains")

    def get_domain(self, **kwargs):
        return self.get_domains(**kwargs)

    def add_domain(self, id):
        data = self.conn._post("/system/domains", {"domain": {"id": id}})
        return data.get("domain")

    def delete_domain(self, id):
        self.conn._delete("/system/domains/{}".format(id))


class Security(Framework):
    def get_policies(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/system/policies/{}".format(kwargs["id"]), params=kwargs)
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
        data = self.conn._put("/system/policies/{}".format(id), {"policy": {"policy": policy}})
        return data.get("policy")


class Services(Framework):
    def get(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/system/services/{}".format(kwargs["id"]), params=kwargs)
        else:
            data = self.conn._get("/system/services", params=kwargs)
        return data.get("service") or data.get("services")

    def create(self, id, config):
        data = self.conn._post("/system/services", {"service": {"id": id, "cfg": config}})
        return data.get("service")

    def start(self, id):
        data = self.conn._put("/system/services/{}".format(id), {"service": {"operation": "start"}})
        return data.get("service")

    def stop(self, id):
        data = self.conn._put("/system/services/{}".format(id), {"service": {"operation": "stop"}})
        return data.get("service")

    def restart(self, id):
        data = self.conn._put("/system/services/{}".format(id), {"service": {"operation": "restart"}})
        return data.get("service")

    def real_restart(self, id):
        data = self.conn._put("/system/services/{}".format(id), {"service": {"operation": "real_restart"}})
        return data.get("service")

    def enable(self, id):
        data = self.conn._put("/system/services/{}".format(id), {"service": {"operation": "enable"}})
        return data.get("service")

    def disable(self, id):
        data = self.conn._put("/system/services/{}".format(id), {"service": {"operation": "disable"}})
        return data.get("service")

    def delete(self, id):
        self.conn._delete("/system/services/{}".format(id))


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
            data = self.conn._get("/system/ssh_keys/{}".format(kwargs["id"]), params=kwargs)
        else:
            data = self.conn._get("/system/ssh_keys", params=kwargs)
        return data.get("ssh_key") or data.get("ssh_keys")

    def get_ssh_key(self, **kwargs):
        return self.get_ssl_keys(**kwargs)

    def add_ssh_key(self, user, key=None, path=None):
        if not key and not path:
            raise GeneralError("Must supply either public `key` (as str) or its `path` on disk")
        if path:
            with open(path, "r") as f:
                key = f.read().rstrip("\n")
        data = self.conn._post("/system/ssh_keys", {"ssh_key": {"user": user, "key": key}})
        return data.get("ssh_key")

    def delete_ssh_key(self, id):
        self.conn._delete("/system/ssh_keys/{}".format(id))

    def shutdown(self):
        self.conn._post("/system/shutdown")

    def reboot(self):
        self.conn._post("/system/reboot")


class Updates(Framework):
    def get(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/updates/{}".format(kwargs["id"]), params=kwargs)
        else:
            data = self.conn._get("/updates", params=kwargs)
        return data.get("update") or data.get("updates")

    def apply(self):
        data = self.conn._post("/updates")
        return data[0]


class Websites(Framework):
    def get(self, **kwargs):
        if kwargs.get("id"):
            data = self.conn._get("/websites/{}".format(kwargs["id"]), params=kwargs)
        else:
            data = self.conn._get("/websites", params=kwargs)
        return data.get("website") or data.get("websites")

    def create(self, id, site_type, addr, port, extra_data={}):
        data = self.conn._post("/websites", {"website": {"id": id, "site_type": site_type,
            "addr": addr, "port": port, "extra_data": extra_data}})
        return (data[0], data[1].get("website"))

    def edit(self, id, new_name="", addr=None, port=None):
        if not new_name and not addr and not port:
            raise GeneralError("Must supply items to edit")
        data = self.conn._get("/websites/{}".format(id))
        data = data.get("website")
        addr = addr or data["addr"]
        port = port or data["port"]
        data = self.conn._put("/websites/{}".format(id), {"website": {"addr": addr, "port": port,
            "new_name": new_name}})
        return data.get("website")

    def enable(self, id):
        data = self.conn._put("/websites/{}".format(id), {"website": {"operation": "enable"}})
        return data.get("website")

    def disable(self, id):
        data = self.conn._put("/websites/{}".format(id), {"website": {"operation": "disable"}})
        return data.get("website")

    def enable_ssl(self, id, cert):
        data = self.conn._put("/websites/{}".format(id), {"website": {"operation": "enable_ssl",
            "cert": cert}})
        return data.get("website")

    def disable_ssl(self, id):
        data = self.conn._put("/websites/{}".format(id), {"website": {"operation": "disable_ssl"}})
        return data.get("website")

    def update(self, id):
        data = self.conn._put("/websites/{}".format(id), {"website": {"operation": "update"}})
        return data.get("website")

    def action(self, id, action):
        self.conn._post("/websites/actions/{}".format(id)+"/"+action)

    def delete(self, id):
        data = self.conn._delete("/websites/{}".format(id))
        return data
