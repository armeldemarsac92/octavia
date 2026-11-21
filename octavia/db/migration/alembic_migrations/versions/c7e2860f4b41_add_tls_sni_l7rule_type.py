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

"""Register the TLS_SNI rule type.

Revision ID: c7e2860f4b41
Revises: 61dc89ad2fb7
"""

from alembic import op
import sqlalchemy as sa


revision = 'c7e2860f4b41'
down_revision = '61dc89ad2fb7'


rule_types = sa.table('l7rule_type', sa.column('name', sa.String(36)))


def upgrade():
    op.bulk_insert(rule_types, [{'name': 'TLS_SNI'}])
