#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

"""Track frontend fallback withdrawal and ownership of provisioning errors.

Revision ID: a6e8c2021f47
Revises: 74a8f3de8c61
"""

from alembic import op
import sqlalchemy as sa


revision = 'a6e8c2021f47'
down_revision = '74a8f3de8c61'


def upgrade():
    op.add_column(
        'listener',
        sa.Column('frontend_fallback_owns_error', sa.Boolean()))
