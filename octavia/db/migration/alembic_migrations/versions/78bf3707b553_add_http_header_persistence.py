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

"""Store the HTTP header session persistence policy."""

from alembic import op
import sqlalchemy as sa


revision = '78bf3707b553'
down_revision = 'c16271db3ef5'


def upgrade():
    persistence = 'session_persistence'
    op.add_column(persistence, sa.Column(
        'header_name', sa.String(256), nullable=True))
    op.add_column(persistence, sa.Column(
        'header_absolute_timeout_ms', sa.BigInteger(), nullable=True))
    op.add_column(persistence, sa.Column(
        'header_persistence_error', sa.Boolean(), nullable=False,
        server_default=sa.false()))
    persistence_types = sa.table(
        'session_persistence_type', sa.column('name', sa.String(36)))
    op.bulk_insert(persistence_types, [{'name': 'HTTP_HEADER'}])
