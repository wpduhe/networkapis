import json


class JSONObject:
    def __init__(self):
        pass

    def json(self, indent: int=None) -> str:
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

        return json.dumps(r, indent=indent)

    @classmethod
    def load(cls, data: dict=None):
        if data:
            obj = cls()

            for k, v in data.items():
                if isinstance(v, dict):
                    obj.__setattr__(k, JSONObject.load(v))
                elif isinstance(v, list):
                    obj.__setattr__(k, list())
                    for x in v:
                        if isinstance(x, dict):
                            obj.__getattribute__(k).append(JSONObject.load(x))
                        else:
                            obj.__getattribute__(k).append(x)
                else:
                    obj.__setattr__(k, v)

            return obj
        else:
            return data

    def dict(self) -> dict:
        return json.loads(self.json())
