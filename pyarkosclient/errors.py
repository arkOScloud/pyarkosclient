class GeneralError(Exception):
    def __init__(self, error):
        self.error = error

    def __str__(self):
        return repr(self.error)


class AuthenticationError(Exception):
    def __str__(self):
        return repr("The server refused to authorize that request. Please verify your provided username/password or API key.")


class ServerError(Exception):
    def __init__(self, code, report):
        self.code = code
        self.report = report

    def __str__(self):
        return repr("The arkOS server encountered an error. (HTTP {})".format(self.code))


class NotFoundError(Exception):
    def __str__(self):
        return repr("The item or function you requested could not be found.")
