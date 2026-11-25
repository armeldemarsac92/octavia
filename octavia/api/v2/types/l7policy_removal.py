# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from wsme.rest import json as wsme_json
from wsme import types as wtypes

from octavia.api.common import types
from octavia.api.v2.types import l7policy
from octavia.api.v2.types.l7policy_activation import Revision
from octavia.i18n import _


class L7PolicyRemovalSnapshot(types.BaseType):
    revision = wtypes.wsattr(wtypes.text)
    loadbalancer_id = wtypes.wsattr(wtypes.UuidType())
    policy = wtypes.wsattr(l7policy.L7PolicyFullResponse)


class L7PolicyRemovalRootResponse(types.BaseType):
    l7policy_removal = wtypes.wsattr(L7PolicyRemovalSnapshot)


class L7PolicyRemovalPOST(types.BaseType):
    expected_revision = wtypes.wsattr(Revision, mandatory=True)


class L7PolicyRemovalRootPOST(types.BaseType):
    l7policy_removal = wtypes.wsattr(L7PolicyRemovalPOST, mandatory=True)


@wsme_json.fromjson.when_object(L7PolicyRemovalRootPOST)
def _l7policy_removal_post_from_json(datatype, value):
    if not isinstance(value, dict) or set(value) != {'l7policy_removal'}:
        raise ValueError(_('Supply an l7policy_removal object.'))
    removal = value['l7policy_removal']
    if (not isinstance(removal, dict) or
            set(removal) != {'expected_revision'} or
            not isinstance(removal['expected_revision'], str)):
        raise ValueError(_('Supply the expected L7 policy removal revision.'))
    return wsme_json.fromjson.default(datatype, value)
