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

"""Add per-policy HTTP external authorization.

Revision ID: 1ce81c9aa2f2
Revises: b11d395eef6d
"""

from alembic import op
import sqlalchemy as sa


revision = '1ce81c9aa2f2'
down_revision = 'b11d395eef6d'


def upgrade():
    op.add_column('l7policy', sa.Column(
        'external_auth', sa.JSON(none_as_null=True)))
    op.create_table(
        'l7policy_external_auth_pool',
        sa.Column('l7policy_id', sa.String(36), nullable=False),
        sa.Column('pool_id', sa.String(36), nullable=False),
        sa.PrimaryKeyConstraint('l7policy_id'),
        sa.ForeignKeyConstraint(
            ['l7policy_id'], ['l7policy.id'], ondelete='CASCADE',
            name='fk_l7policy_ext_auth_l7policy_id'),
        sa.ForeignKeyConstraint(
            ['pool_id'], ['pool.id'], name='fk_l7policy_ext_auth_pool_id'))
    op.create_index('ix_l7policy_external_auth_pool_pool_id',
                    'l7policy_external_auth_pool', ['pool_id'])
