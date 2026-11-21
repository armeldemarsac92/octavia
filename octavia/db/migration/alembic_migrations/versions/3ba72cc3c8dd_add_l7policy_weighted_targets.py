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

"""add ordered weighted destinations to L7 policies

Revision ID: 3ba72cc3c8dd
Revises: 4eca7fc8054a
"""

from alembic import op
import sqlalchemy as sa


revision = '3ba72cc3c8dd'
down_revision = '4eca7fc8054a'


def upgrade():
    op.create_table(
        'l7policy_target',
        sa.Column('l7policy_id', sa.String(36), primary_key=True),
        sa.Column('position', sa.Integer, primary_key=True),
        sa.Column('weight', sa.Integer, nullable=False),
        sa.Column('pool_id', sa.String(36), index=True),
        sa.Column('status_code', sa.Integer),
        sa.ForeignKeyConstraint(
            ['l7policy_id'], ['l7policy.id'],
            name='fk_l7policy_target_l7policy_id', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(
            ['pool_id'], ['pool.id'], name='fk_l7policy_target_pool_id'),
        sa.CheckConstraint(
            "(pool_id IS NULL AND status_code IS NOT NULL) OR "
            "(pool_id IS NOT NULL AND status_code IS NULL)",
            name='ck_l7policy_target_destination'),
    )
    actions = sa.table('l7policy_action', sa.column('name', sa.String(36)))
    op.bulk_insert(actions, [{'name': 'WEIGHTED_TARGETS'}])
