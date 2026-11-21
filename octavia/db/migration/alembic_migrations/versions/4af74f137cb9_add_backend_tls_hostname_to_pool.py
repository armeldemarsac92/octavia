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

"""Add a DNS identity for the backend TLS connection."""

from alembic import op
import sqlalchemy as sa


revision = '4af74f137cb9'
down_revision = 'e4c57b2d836f'


def upgrade():
    op.add_column('pool', sa.Column('backend_tls_hostname',
                                    sa.String(253), nullable=True))
