# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from alembic import op
import sqlalchemy as sa


revision = '0e79b45b8674'
down_revision = '12de6b42a091'


def upgrade():
    op.add_column('listener', sa.Column(
        'l7policy_listener_update', sa.JSON(none_as_null=True)))
