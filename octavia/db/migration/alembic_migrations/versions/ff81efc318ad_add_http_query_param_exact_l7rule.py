#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

"""Register the HTTP_QUERY_PARAM_EXACT rule and widen its key.

Revision ID: ff81efc318ad
Revises: 9372b8ac16d4
"""

from alembic import op
import sqlalchemy as sa


revision = 'ff81efc318ad'
down_revision = '9372b8ac16d4'


rule_types = sa.table('l7rule_type', sa.column('name', sa.String(36)))


def upgrade():
    with op.batch_alter_table('l7rule') as batch_op:
        batch_op.alter_column('key', existing_type=sa.String(255),
                              existing_nullable=True, type_=sa.String(256))
    op.bulk_insert(rule_types, [{'name': 'HTTP_QUERY_PARAM_EXACT'}])
