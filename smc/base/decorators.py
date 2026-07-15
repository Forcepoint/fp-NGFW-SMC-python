#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
"""
Decorators used in various areas throughout smc-python.
"""
from __future__ import annotations

import warnings
import functools
from typing import TypeVar, Callable, Any, Optional, Union, Iterator

_F = TypeVar("_F", bound=Callable[..., Any])


def deprecated(func_replacement: str) -> Callable[[_F], _F]:
    """
    Use this decorator on functions that are marked as deprecated.
    It takes a single argument of the function name it's being
    replaced with.
    """

    def _deprecated(func: _F) -> _F:
        @functools.wraps(func)
        def new_func(*args: Any, **kwargs: Any) -> Any:
            warnings.simplefilter("always", DeprecationWarning)  # turn off filter
            warnings.warn(
                "Call to deprecated function {}. Use new function: {}() instead.".format(
                    func.__name__, func_replacement
                ),
                category=DeprecationWarning,
                stacklevel=2,
            )
            warnings.simplefilter("default", DeprecationWarning)  # reset filter
            return func(*args, **kwargs)

        return new_func  # type: ignore[return-value]

    return _deprecated  # type: ignore[return-value]


class classproperty(object):
    """
    Used for collection manager so objects can be accessed as a
    class property and also from the instance
    """

    def __init__(self, fget: Callable[..., Any]) -> None:
        self.fget = fget

    def __get__(self, instance: Any, owner_cls: Any) -> Any:
        return self.fget(owner_cls)


def memoize(f: Callable[..., Any]) -> Callable[..., Any]:
    memo: dict[Any, Any] = {}

    def helper(x: Any) -> Any:
        if x not in memo:
            memo[x] = f(x)
        return memo[x]

    return helper


def cacheable_resource(func: Callable[..., Any]) -> Any:
    @functools.wraps(func)
    def get(self: Any) -> Any:
        try:
            return self._cache[func]
        except AttributeError:
            self._cache = {}
        except KeyError:
            pass
        ret = self._cache[func] = func(self)
        return ret

    return property(get)


class cached_property(object):
    """
    Use for caching a property value on the instance. If the
    attribute is deleted, it will be recreated when called.
    """

    def __init__(self, func: Callable[..., Any]) -> None:
        self.func = func
        # self.__doc__ = func.__doc__

    def __get__(self, obj: Any, cls: Any) -> Any:
        if obj is None:
            return self
        value = obj.__dict__[self.func.__name__] = self.func(obj)
        return value


def create_hook(function: _F) -> _F:
    """
    Provide a pre-filter to the create function that provides the ability
    to modify the element json before submitting to the SMC. To register
    a create hook, set on the class or top level Element class to enable
    this on any descendent of Element::

        Element._create_hook = classmethod(myhook)

    The hook should be a callable and take two arguments, cls, json and
    return the json after modification. For example::

        def myhook(cls, json):
            print("Called with class: %s" % cls)
            if 'address' in json:
                json['address'] = '2.2.2.2'
            return json
    """

    @functools.wraps(function)
    def run(cls: Any, json: Any, **kwargs: Any) -> Any:
        if hasattr(cls, "_create_hook"):
            json = cls._create_hook(json)
        return function(cls, json, **kwargs)

    return run  # type: ignore[return-value]


def exception(function: Callable[..., Any]) -> Callable[..., Any]:
    """
    If exception was specified for prepared_request,
    inject this into SMCRequest so it can be used for
    return if needed.
    """

    @functools.wraps(function)
    def wrapper(*exception: Any, **kwargs: Any) -> Any:
        result = function(**kwargs)
        if exception:
            result.exception = exception[0]
        return result

    return wrapper


def with_metaclass(mcls: Any) -> Callable[[Any], Any]:
    """
    Metaclass class decorator for py2 and py3
    """

    def decorator(cls: Any) -> Any:
        body = vars(cls).copy()
        # clean out class body
        body.pop("__dict__", None)
        body.pop("__weakref__", None)
        return mcls(cls.__name__, cls.__bases__, body)

    return decorator
