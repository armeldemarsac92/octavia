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

"""Store backend TLS system CA opt-in and its peer-bound attestation."""

from alembic import op
import sqlalchemy as sa


revision = 'c16271db3ef5'
down_revision = '1c4fd3a0b279'


def upgrade():
    op.add_column('pool', sa.Column(
        'backend_tls_system_ca', sa.Boolean(), server_default=sa.false(),
        nullable=False))
    op.add_column('pool', sa.Column(
        'backend_tls_system_ca_sha256', sa.String(64), nullable=True))
    op.add_column('pool', sa.Column(
        'backend_tls_system_ca_peers', sa.JSON(none_as_null=True)))
