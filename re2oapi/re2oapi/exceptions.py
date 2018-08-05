class APIClientGenericError(ValueError):
    template = "{}"

    def __init__(self, *data):
        self.data = data
        self.message = self.template.format(*data)
        super(APIClientGenericError, self).__init__(self.message)


class InvalidCredentials(APIClientGenericError):
    template = "The credentials for {}@{} are not valid."


class PermissionDenied(APIClientGenericError):
    template = "The {} request to '{}' was denied for {}."


class TokenFileNotFound(APIClientGenericError):
    template = "Token file at {} not found."


class TokenFileNotReadable(APIClientGenericError):
    template = "Token file at {} is not a JSON readable file."


class TokenNotInTokenFile(APIClientGenericError):
    template = "Token for {}@{} not found in token file ({})."
