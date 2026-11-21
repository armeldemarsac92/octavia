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

"""Register the HTTP_HEADER_EXACT rule and widen its key and value.

Revision ID: e9c83aa47e21
Revises: c7e2860f4b41
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql


revision = 'e9c83aa47e21'
down_revision = 'c7e2860f4b41'


rule_types = sa.table('l7rule_type', sa.column('name', sa.String(36)))


def upgrade():
    value_type = sa.String(4096).with_variant(
        mysql.VARCHAR(4096, charset='utf8mb4'), 'mysql', 'mariadb')
    with op.batch_alter_table('l7rule') as batch_op:
        batch_op.alter_column('key', existing_type=sa.String(255),
                              existing_nullable=True, type_=sa.String(256))
        batch_op.alter_column('value', existing_type=sa.String(255),
                              existing_nullable=False, type_=value_type)
    op.bulk_insert(rule_types, [{'name': 'HTTP_HEADER_EXACT'}])
