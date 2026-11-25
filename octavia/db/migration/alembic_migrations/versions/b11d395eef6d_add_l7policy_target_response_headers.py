#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Store response header modifiers on individual weighted targets."""

from alembic import op
import sqlalchemy as sa


revision = 'b11d395eef6d'
down_revision = '78bf3707b553'


def upgrade():
    op.add_column('l7policy_target',
                  sa.Column('response_header_operations', sa.JSON()))
