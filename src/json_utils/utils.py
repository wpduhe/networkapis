import json


class JSONObject:
    def __init__(self, data: dict):
        for key, value in data.items():
            if isinstance(value, dict):
                self.__setattr__(key, JSONObject(value))
            elif isinstance(value, list):
                self.__setattr__(key, list())
                for x in value:
                    if isinstance(x, dict):
                        self.__getattribute__(key).append(JSONObject(x))
                    else:
                        self.__getattribute__(key).append(x)
            else:
                self.__setattr__(key, value)

    def json(self):
        r = {}
        for attr in self.__dict__:
            if type(self.__getattribute__(attr)) is type(self):
                r[attr] = self.__getattribute__(attr).dict()
            elif isinstance(self.__getattribute__(attr), list):
                r[attr] = list()
                for x in self.__getattribute__(attr):
                    if type(x) is type(self):
                        r[attr].append(x.dict())
                    else:
                        r[attr].append(x)
            else:
                r[attr] = self.__getattribute__(attr)

        return json.dumps(r, indent=4)

    def dict(self):
        return json.loads(self.json())
