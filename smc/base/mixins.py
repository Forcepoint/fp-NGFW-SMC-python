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

from smc.api.exceptions import ActionCommandFailed, ResourceNotFound
from smc.api.common import SMCRequest


class RequestAction(object):
    """
    A Generic request action provides a simple interface to
    building and executing an SMCRequest. This will raise
    the exception specified if the resource is not found.

    Valid parameters that can be provided in kwargs are:

    :param str method: method for which to call. Can be
        'read', 'create', 'update' or 'delete' (default: 'read')
    :param str resource: The element resource to act on. If the
        href is already known, this can be provided as href
    :param bool raw_result: Return the raw SMCResult
    """

    def make_request(self, *exception, **kwargs):
        raw_result = kwargs.pop("raw_result", False)
        method = kwargs.pop("method", "read")
        ex = exception[0] if exception else ActionCommandFailed
        if "resource" in kwargs:
            try:
                kwargs.update(href=self.data.get_link(kwargs.pop("resource")))
            except ResourceNotFound as e:
                raise ex(e)

        request = SMCRequest(**kwargs)
        request.exception = ex
        result = getattr(request, method)()
        if raw_result:
            return result
        return result.json


class UnicodeMixin(object):
    """
    Mixin used to stage for supporting python 3. After py2 support is dropped
    then this can be removed. Py2 requires that __str__ returns bytes whereas
    py3 should return unicode. Each py2 supported class will have a __unicode__
    method.

    Consider migrating to future module and use their class decorator
    from future.utils import python_2_unicode_compatible
    \\@python_2_unicode_compatible
    From: http://python-future.org/what_else.html
    """

    import sys

    if sys.version_info > (3, 0):

        def __str__(x):
            return x.__unicode__()

    else:

        def __str__(x):
            return unicode(x).encode("utf-8")
