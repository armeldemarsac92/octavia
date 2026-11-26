# Copyright 2026
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from alembic import op
import sqlalchemy as sa

revision = '12de6b42a091'
down_revision = '047259f107e6'


def upgrade():
    op.add_column('listener', sa.Column('tcp_default_targets', sa.JSON()))
    op.add_column('listener', sa.Column(
        'tcp_default_targets_revision', sa.String(36)))
    op.add_column('listener', sa.Column(
        'tcp_default_targets_status', sa.String(16)))
    op.add_column('listener', sa.Column(
        'tcp_default_targets_applied', sa.JSON()))
    op.add_column('listener', sa.Column(
        'tcp_default_targets_restrictive', sa.Boolean()))
    op.create_table(
        'listener_tcp_default_target_pool',
        sa.Column('listener_id', sa.String(36), nullable=False),
        sa.Column('pool_id', sa.String(36), nullable=False),
        sa.PrimaryKeyConstraint('listener_id', 'pool_id'),
        sa.ForeignKeyConstraint(
            ['listener_id'], ['listener.id'], ondelete='CASCADE',
            name='fk_tcp_default_target_listener_id'),
        sa.ForeignKeyConstraint(
            ['pool_id'], ['pool.id'], name='fk_tcp_default_target_pool_id'))
    op.create_index(op.f('ix_listener_tcp_default_target_pool_pool_id'),
                    'listener_tcp_default_target_pool', ['pool_id'])
