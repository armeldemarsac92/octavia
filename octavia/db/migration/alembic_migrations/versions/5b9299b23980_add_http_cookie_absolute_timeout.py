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

"""Persist absolute HTTP session cookie timeouts."""

from alembic import op
import sqlalchemy as sa


revision = '5b9299b23980'
down_revision = 'c7fb7ad0d915'


def upgrade():
    op.add_column('session_persistence', sa.Column(
        'cookie_absolute_timeout_ms', sa.BigInteger(), nullable=True))
    op.add_column('session_persistence', sa.Column(
        'cookie_scope', sa.String(64), nullable=True))
