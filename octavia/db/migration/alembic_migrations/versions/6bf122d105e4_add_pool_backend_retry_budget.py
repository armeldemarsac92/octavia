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

"""Add a retry budget to HTTP pools.

Revision ID: 6bf122d105e4
Revises: cadb700cba48
"""

from alembic import op
import sqlalchemy as sa

revision = '6bf122d105e4'
down_revision = 'cadb700cba48'


def upgrade():
    op.add_column('pool', sa.Column(
        'backend_retry_budget', sa.JSON(none_as_null=True)))
