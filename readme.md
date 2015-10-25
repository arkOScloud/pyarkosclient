# pyarkOSclient

Python bindings for remote management of arkOS servers via their Kraken REST API


## To use

*(NOTE this documentation is different than the documentation for the server-side arkOS management libraries. Please see the appropriate repo for more information. This should only be used for the client-side bindings.)*

All methods are accessible by creating a main arkOS connection object. Methods will return either:

 * dictionary objects (for most methods that GET/POST data)
 * a Job object and a dictionary object in a tuple (for long-running processes like app or website installation)
 * `None` (for most delete calls)
 * other data, when otherwise specified.

Login with a username and password (token lasts for one hour, refresh with `arkos.refresh_token()`):

```
>>> from pyarkosclient import arkOS
>>> arkos = arkOS(host="http://localhost:8000", username="myuser", password="mypass")
```

or with a prior-created API key (no refresh necessary):

```
>>> from pyarkosclient import arkOS
>>> arkos = arkOS(host="http://localhost:8000", api_key="xxxxx")
```

## Job objects

Long-running processes like app or website installation will return Job objects for tracking the process of your commands in an asynchronous way. The Job object will be returned as long as the server has accepted your command and there were no problems understanding it.

Job objects have two properties: `id` being the Job ID, and `status` being a string that represents the job's present status. `status` can be `"running"` if the job is still running, `"error_request"` if it failed due to a request problem, `"error_server"` if the server encountered an exception while running the job, or `"success"` if the job finished running without problems. It must be periodically refreshed in order to get the most up-to-date information.

For example, if you wanted to create a website and wait synchronously for it to finish using the Job object, you could do something like:

```
>>> job = arkos.websites.create("mysite", "wordpress", "localhost", 80)
>>> job
<Job 370f80f95fcf7c4e>
>>> job.status
'running'
>>> while job.status == "running":
...    time.sleep(2)
...    job.check()
...
>>> job.status    # 30 seconds later...
'success'
```


## Methods

### arkos.apikeys

 * Get API key: `arkos.apikeys.get()`
 * Create API key: `arkos.apikeys.add("username")`


### arkos.applications

 * Get applications: `arkos.applications.get()`
   * Optional arguments: `rescan` (bool), `type` (str), `loadable` (bool), `installed` (bool)
 * Get application details: `arkos.applications.get(id="appname")`
 * Install or upgrade application: `arkos.applications.install("appname")`
 * Uninstall application: `arkos.applications.uninstall("appname")`


### arkos.backups

 * Get backups: `arkos.backups.get()`
 * Get all backups for app: `arkos.backups.get(id="appname")`
 * Get backup details: `arkos.backups.get(id="appname", time="201510251726")`
 * Get apps with backup ability: `arkos.backup.get_types()`
 * Create backup: `arkos.backup.create("appname")`
 * Restore backup: `arkos.backup.restore("appname", "201510251726")`
 * Delete backup: `arkos.backup.delete("appname", "201510251726")`


### arkos.certificates

 * Get certificates: `arkos.certificates.get()`
   * Optional arguments: `rescan` (bool)
 * Get certificate details: `arkos.certificates.get(id="certname")`
 * Get certificate authorities: `arkos.certificates.get_authorities()`
 * Get certificate authority details: `arkos.certificates.get_authority(id="authname")`
 * Get apps/sites with SSL/TLS ability: `arkos.certificates.get_possible_assigns()`
 * Download certificate authority: `arkos.certificates.download_authority("authname")` (Returns cert as raw string)
 * Generate self-signed certificate: `arkos.certificates.generate(name, domain, country, state, locale, email, keytype="RSA", keylength=2048)`
 * Upload certificate: `arkos.certificates.upload(name, cert, key, chain=None)`
   * `cert` and `key` can be either paths to the respective file on your client filesystem, or opened file/StringIO objects.
 * Assign certificate to apps/sites: `arkos.certificates.assign(id, atype=None, app_id=None, special_id=None, assign=None)`
   * `atype` can be `"genesis"`, `"app"` or `"site"`. Site types must have `app_id`. App types must have `app_id` and `special_id`. Or you can manually create your assign object and pass to `assign` and skip the rest.
 * Unassign certificate to apps/sites: `arkos.certificates.unassign(id, atype=None, app_id=None, special_id=None, assign=None)`
   * Follows same convention as above.
 * Delete certificate: `arkos.certificates.delete("certname")`
 * Delete certificate authority: `arkos.certificates.delete_authority("certname")`


### arkos.config

 * Get config: `arkos.config.get()`
   * Config is cached locally. Make sure to save and reload when necessary.
 * Get individual config section: `arkos.config.get("section")`
 * Get individual config key: `arkos.config.get("section", "key")`
   * Optional arguments: `default` to return if key does not exist. Defaults to `None`.
 * Set entire config section: `arkos.config.set("section", {"data": "to_add"})`
 * Set individual config key: `arkos.config.set("section", "key", "value")`
 * Save changes: `arkos.config.save()`
 * Refresh cached config: `arkos.config.refresh()`


### arkos.databases

 * Get databases: `arkos.databases.get()`
   * Optional arguments: `rescan` (bool)
 * Get database details: `arkos.databases.get(id="dbname")`
 * Get database users: `arkos.databases.get_users()`
   * Optional arguments: `rescan` (bool)
 * Get database types: `arkos.databases.get_types()`
 * Get database user details: `arkos.databases.get_user(id="username")`
 * Add database: `arkos.databases.add("dbname", "db-type")`
 * Add database user: `arkos.databases.add_user("username", "db-type")`
 * Execute SQL code on database: `arkos.databases.execute("dbname", "SELECT * FROM tblname")`
 * Dump database: `arkos.databases.dump("dbname")` Returns raw database dump as string.
 * Change user permissions: `arkos.databases.user_chmod("username", action, "dbname")`
   * `action` being either `grant`, `revoke` or `check`.
 * Delete database: `arkos.databases.delete("dbname")`
 * Delete database user: `arkos.databases.delete_user("username")`


### arkos.files

 * Get file/folder information: `arkos.files.get("/path/to/file/or/folder")`
 * Get fileshare links: `arkos.files.get_shares()`
 * Get fileshare link details: `arkos.files.get_share("xxxxx")`
 * Create empty file: `arkos.files.create_file("/path/to/file")`
 * Create empty folder: `arkos.files.create_folder("/path/to/folder")`
 * Upload file(s) to server: `arkos.files.upload("/path/to/upload/into", ["list", "of", "filenames"])`
   * The list of filenames can also contain file/StringIO objects.
 * Download file/folder from server: `arkos.files.download("/path/to/download")` Returns raw file contents as string.
   * Folders are downloaded as archive files, created on-the-fly. Optional arguments: `save_to` (path), save the file here instead of returning its contents.
 * Copy file/folder: `arkos.files.copy("/path/from", "/path/into/")`
 * Move or rename file/folder: `arkos.files.rename("/path/from", "/path/to")`
 * Extract archive: `arkos.files.extract("/path/to/archive.tar.gz")`
 * Change permissions: `arkos.files.chmod("/path/to/file", 0700)`
 * Change owner: `arkos.files.chown("/path/to/file", user="username", group="groupname")`
   * Can set either `user` or `group` or both.
 * Quick file edit: `arkos.files.edit("/path/to/file", "text-of-file-to-save")`
 * Delete file/folder: `arkos.files.delete("/path/to/file")`
 * Create fileshare link: `arkos.files.share("/path/to/file", until)`
   * `until` being a datetime object or an epoch timestamp (as int). `0` makes the link only valid for one use.
 * Update fileshare link: `arkos.files.update_share("xxxxxx", until)`
   * Follows same convention as above.
 * Remove fileshare link: `arkos.files.remove_share("xxxxxx")`


### arkos.filesystems

 * Get filesystems: `arkos.filesystems.get()`
 * Get filesystem details: `arkos.filesystems.get(id="/dev/sda1")`
 * Get filesystem points of interest: `arkos.filesystems.get_points()`
 * Create virtual disk: `arkos.filesystems.create_virtual("mydisk", size=1024, crypt=True, passwd="mypass")`
   * `size` numbered in megabytes. `crypt` if you want the disk to be encrypted. `passwd` only required for encrypted disks.
 * Mount disk: `arkos.filesystems.mount("mydisk")`
   * Optional arguments: `passwd` (str). Required if the disk in question is encrypted.
 * Unmount disk: `arkos.filesystems.umount("mydisk")`
 * Enable mounting disk on each boot: `arkos.filesystems.enable("mydisk")`
 * Disable mounting disk on each boot: `arkos.filesystems.disable("mydisk")`
 * Delete virtual disk: `arkos.filesystems.delete("mydisk")`


### arkos.networks

 * Get networks: `arkos.networks.get()`
 * Get network details: `arkos.networks.get(id="mynetwork")`
 * Get network interfaces: `arkos.networks.get_interfaces()`
 * Get network interface details: `arkos.networks.get_interface(id="enp0s3")`
 * Add network: `arkos.networks.add("mynetwork", config)`
   * `config` being a dictionary object with keys/values representing Arch Linux netctl configuration data.
 * Connect to network: `arkos.networks.connect("mynetwork")`
 * Disconnect from network: `arkos.networks.disconnect("mynetwork")`
 * Enable network connection on boot: `arkos.networks.enable("mynetwork")`
 * Disable network connection on boot: `arkos.networks.disable("mynetwork")`
 * Delete network configuration: `arkos.networks.delete("mynetwork")`


### arkos.packages

 * Get available and installed system packages: `arkos.packages.get()`
 * Get system package details: `arkos.packages.get(id="arkos-core")`
 * Install package(s): `arkos.packages.install(["packages", "to", "install"])`
 * Remove package(s): `arkos.packages.remove(["packages", "to", "remove"])`


### arkos.roles

 * Get users: `arkos.roles.get_users()`
 * Get user details: `arkos.roles.get_user(id=1000)`
 * Get groups: `arkos.roles.get_groups()`
 * Get group details: `arkos.roles.get_group(id=1000)`
 * Get domains: `arkos.roles.get_domains()`
 * Get domain details: `arkos.roles.get_domain(id="mydomain.xyz")`
 * Add user: `arkos.roles.add_user("username", "passwd", "mydomain.xyz", "first_name", "last_name", admin=True, sudo=True)`
 * Add group: `arkos.roles.add_group("groupname", ["list", "of", "member", "users"])`
 * Add domain: `arkos.roles.add_domain("mydomain.xyz")`
 * Edit user: `arkos.roles.edit_user("username", "passwd", "mydomain.xyz", "first_name", "last_name", admin=True, sudo=True, mail_addresses=["myalias@mydomain.xyz"])`
   * All arguments except `username` are optional. Leave the argument blank if you do not want to change it.
 * Edit group: `arkos.roles.edit_group("groupname", ["list", "of", "member", "users"])`
 * Delete user: `arkos.roles.delete_user("username")`
 * Delete group: `arkos.roles.delete_group("groupname")`
 * Delete domain: `arkos.roles.delete_domain("mydomain.xyz")`


### arkos.security

 * Get firewall policies: `arkos.security.get_policies()`
 * Get firewall policy details: `arkos.security.get_policy(id="appname")`
 * Update firewall policy: `arkos.security.get_policy("appname", policy)`
   * `policy` being either `"allow"`, `"local"` or `"none"`


### arkos.services

 * Get system services: `arkos.services.get()`
 * Get system service details: `arkos.services.get(id="svcname")`
 * Create system service: `arkos.services.create("svcname", config)`
   * Uses Supervisor. `config` being a dictionary object with keys/values as Supervisor configuration data.
 * Start service: `arkos.services.start("svcname")`
 * Stop service: `arkos.services.stop("svcname")`
 * Restart or reload service: `arkos.services.restart("svcname")`
 * Force restart service: `arkos.services.real_restart("svcname")`
 * Enable service start on boot: `arkos.services.enable("svcname")`
 * Disable service start on boot: `arkos.services.disable("svcname")`
 * Delete Supervisor service: `arkos.services.delete("svcname")`


### arkos.system

 * Get system time and NTP offset of server: `arkos.system.get_time()`
 * Set system time of server from NTP: `arkos.system.set_time()`
 * Get system stats (CPU, memory use, etc): `arkos.system.get_stats()`
 * Get SSH keys: `arkos.system.get_ssh_keys()`
 * Get SSH key details: `arkos.system.get_ssh_key(id="key-id")`
 * Add SSH key: `arkos.system.add_ssh_key("username", key="ssh-rsa xxxxxxx...")`
   * Optional arguments: path (path). Set this to path of SSH public key on local filesystem to upload, and skip the `key` value.
 * Delete SSH key: `arkos.system.delete_ssh_key("key-id")`
 * Shutdown system: `arkos.system.shutdown()`
 * Reboot system: `arkos.system.reboot()`


### arkos.updates

 * Get available updates: `arkos.updates.get()`
 * Get update details: `arkos.updates.get(id=1)`
 * Apply pending updates: `arkos.updates.apply()`


### arkos.websites

 * Get websites: `arkos.websites.get()`
 * Get website details: `arkos.websites.get(id="mysite")`
 * Create website: `arkos.websites.create("mysite", "wordpress", "mydomain.xyz", 80, extra_data={})`
   * `extra_data` should provide additional information required by the website type on site creation. This is not yet documented via the API.
 * Edit website details: `arkos.websites.edit("mysite", new_name="newsite", addr="mydomain.xyz", port=8080)`
   * All arguments except the site name are optional. Leave the argument blank if you do not want to change it.
 * Enable website: `arkos.websites.enable("mysite")`
 * Disable website: `arkos.websites.disable("mysite")`
 * Enable SSL/TLS for website: `arkos.websites.enable_ssl("mysite", "certname")`
 * Disable SSL/TLS for website: `arkos.websites.disable_ssl("mysite")`
 * Update site: `arkos.websites.update("mysite")`
 * Perform a site action: `arkos.websites.action("mysite", "action_name")`
 * Delete site: `arkos.websites.delete("mysite")` Returns a Job object only.
