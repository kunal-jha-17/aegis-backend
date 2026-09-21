"""
TEST-ONLY SHIM — not the real pydantic. This sandbox has no network access
(pip install fails: "host_not_allowed"), so the real pydantic==2.13.5 pinned
in requirements.txt cannot be installed here. This shim implements just
enough of BaseModel's surface (constructor validation, model_dump,
model_dump_json, model_validate_json, model_copy) to actually execute
Part 1/2/3/4's logic during integration testing, instead of only checking
syntax. It does NOT implement real type coercion/validation the way
pydantic does — re-run the real test suite with the real package installed
(see requirements.txt) before trusting this beyond "the logic paths run
without crashing."
"""
import json
from enum import Enum


class ValidationError(Exception):
    pass


def _all_annotations(cls):
    ann = {}
    for base in reversed(cls.__mro__):
        ann.update(getattr(base, "__annotations__", {}))
    return ann


def _dump(value, mode):
    if isinstance(value, BaseModel):
        return {k: _dump(getattr(value, k), mode) for k in _all_annotations(type(value))}
    if isinstance(value, Enum):
        return value.value if mode == "json" else value
    if isinstance(value, dict):
        return {k: _dump(v, mode) for k, v in value.items()}
    if isinstance(value, list):
        return [_dump(v, mode) for v in value]
    return value


class BaseModel:
    def __init__(self, **data):
        cls = type(self)
        annotations = _all_annotations(cls)
        for name in annotations:
            if name in data:
                setattr(self, name, data[name])
            elif hasattr(cls, name):
                setattr(self, name, getattr(cls, name))
            else:
                raise ValidationError(f"{cls.__name__}: missing required field '{name}'")

    def model_dump(self, mode="python", exclude=None):
        result = _dump(self, mode)
        if exclude:
            for k in exclude:
                result.pop(k, None)
        return result

    def model_dump_json(self):
        return json.dumps(self.model_dump(mode="json"), sort_keys=False)

    @classmethod
    def model_validate_json(cls, text):
        return cls(**json.loads(text))

    @classmethod
    def model_validate(cls, obj):
        if isinstance(obj, cls):
            return obj
        if isinstance(obj, dict):
            return cls(**obj)
        return cls(**{k: getattr(obj, k) for k in _all_annotations(cls)})

    def model_copy(self, update=None):
        data = {k: getattr(self, k) for k in _all_annotations(type(self))}
        if update:
            data.update(update)
        return type(self)(**data)

    def __repr__(self):
        fields = ", ".join(f"{k}={getattr(self, k)!r}" for k in _all_annotations(type(self)))
        return f"{type(self).__name__}({fields})"
