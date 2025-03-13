class MockResponse:  # pylint: disable=too-few-public-methods
    """A mock of a request Response object"""

    def __init__(self, status_code, json_data):
        self.status_code = status_code
        self._json_data = json_data

    def json(self):
        return self._json_data
