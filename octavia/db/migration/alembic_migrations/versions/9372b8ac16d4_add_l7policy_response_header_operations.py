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

"""store response header operations on L7 policies

Revision ID: 9372b8ac16d4
Revises: b681388ab702
"""

from alembic import op
import sqlalchemy as sa


revision = '9372b8ac16d4'
down_revision = 'b681388ab702'


def upgrade():
    op.add_column(
        'l7policy',
        sa.Column('response_header_operations', sa.JSON(none_as_null=True)))
