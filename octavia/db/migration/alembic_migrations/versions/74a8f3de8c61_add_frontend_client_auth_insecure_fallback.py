#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Add insecure fallback for HTTPS client certificate validation.

Revision ID: 74a8f3de8c61
Revises: f47b6c1d9a20
"""

from alembic import op
import sqlalchemy as sa


revision = '74a8f3de8c61'
down_revision = 'f47b6c1d9a20'


def upgrade():
    op.add_column(
        'listener',
        sa.Column('client_authentication_insecure_fallback', sa.Boolean()))
