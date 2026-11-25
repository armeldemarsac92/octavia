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

"""Store ordered HTTP request mirror destinations with pool references.

Revision ID: b22da9155c2b
Revises: d3d72b90b815
"""

from alembic import op
import sqlalchemy as sa


revision = 'b22da9155c2b'
down_revision = 'd3d72b90b815'


def upgrade():
    op.create_table(
        'l7policy_mirror',
        sa.Column('l7policy_id', sa.String(36), primary_key=True),
        sa.Column('target_position', sa.Integer(), primary_key=True),
        sa.Column('position', sa.Integer(), primary_key=True),
        sa.Column('pool_id', sa.String(36), nullable=False),
        sa.Column('numerator', sa.Integer(), nullable=False),
        sa.Column('denominator', sa.Integer(), nullable=False),
        sa.Column('phase', sa.String(32)),
        sa.CheckConstraint(
            'numerator >= 0 AND numerator <= denominator AND '
            'denominator BETWEEN 1 AND 2147483647',
            name='ck_l7policy_mirror_ratio'),
        sa.ForeignKeyConstraint(
            ['l7policy_id'], ['l7policy.id'], ondelete='CASCADE',
            name='fk_l7policy_mirror_l7policy_id'),
        sa.ForeignKeyConstraint(
            ['pool_id'], ['pool.id'], name='fk_l7policy_mirror_pool_id'))
    op.create_index('ix_l7policy_mirror_pool_id', 'l7policy_mirror',
                    ['pool_id'])
