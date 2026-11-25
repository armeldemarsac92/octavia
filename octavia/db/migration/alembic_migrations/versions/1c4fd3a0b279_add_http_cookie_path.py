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

"""Store the optional HTTP cookie path."""

from alembic import op
import sqlalchemy as sa


revision = '1c4fd3a0b279'
down_revision = 'b3d57e9a2c41'


def upgrade():
    op.add_column('session_persistence', sa.Column(
        'cookie_path', sa.String(1024), nullable=True))
