# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Register the HTTP_PATH_LITERAL L7 rule.

Revision ID: e82a623f3439
Revises: 1ce81c9aa2f2
"""

from alembic import op
import sqlalchemy as sa

revision = 'e82a623f3439'
down_revision = '1ce81c9aa2f2'


def upgrade():
    rule_types = sa.table('l7rule_type', sa.column('name', sa.String(36)))
    op.bulk_insert(rule_types, [{'name': 'HTTP_PATH_LITERAL'}])
