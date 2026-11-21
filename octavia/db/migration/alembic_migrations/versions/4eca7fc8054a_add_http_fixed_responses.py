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

"""add local HTTP responses to listeners and L7 policies

Revision ID: 4eca7fc8054a
Revises: fabf4983846b
"""

from alembic import op
import sqlalchemy as sa


revision = '4eca7fc8054a'
down_revision = 'fabf4983846b'


def upgrade():
    op.add_column('listener', sa.Column(
        'default_http_response', sa.JSON(none_as_null=True)))
    op.add_column('l7policy', sa.Column(
        'fixed_response', sa.JSON(none_as_null=True)))
    actions = sa.table('l7policy_action', sa.column('name', sa.String(36)))
    op.bulk_insert(actions, [{'name': 'FIXED_RESPONSE'}])
