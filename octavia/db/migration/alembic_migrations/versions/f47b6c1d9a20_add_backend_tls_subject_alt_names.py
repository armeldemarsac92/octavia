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

"""Add explicit subject alternative names for backend TLS.

Revision ID: f47b6c1d9a20
Revises: cc7a1218b24e
"""

from alembic import op
import sqlalchemy as sa


revision = 'f47b6c1d9a20'
down_revision = 'cc7a1218b24e'


def upgrade():
    op.add_column(
        'pool',
        sa.Column('backend_tls_subject_alt_names', sa.JSON(none_as_null=True)))
