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

"""Store structured L7 request URL rewrites.

Revision ID: 36ab5d95ca27
Revises: 675c8279483a
"""

from alembic import op
import sqlalchemy as sa


revision = '36ab5d95ca27'
down_revision = '675c8279483a'


def upgrade():
    op.add_column('l7policy', sa.Column('request_url_rewrite', sa.JSON()))
