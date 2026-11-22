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

"""Store CORS filters on forwarding L7 policies.

Revision ID: c9b157a8be42
Revises: 7624a16d39be
"""

from alembic import op
import sqlalchemy as sa


revision = 'c9b157a8be42'
down_revision = '7624a16d39be'


def upgrade():
    op.add_column(
        'l7policy', sa.Column('request_cors', sa.JSON(none_as_null=True)))
