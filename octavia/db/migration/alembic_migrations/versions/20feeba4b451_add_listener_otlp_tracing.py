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

"""Add optional OTLP tracing to HTTP listeners.

Revision ID: 20feeba4b451
Revises: 6bf122d105e4
"""

from alembic import op
import sqlalchemy as sa

revision = '20feeba4b451'
down_revision = '6bf122d105e4'


def upgrade():
    op.add_column('listener', sa.Column(
        'otlp_tracing', sa.JSON(none_as_null=True)))
    op.add_column('listener', sa.Column(
        'otlp_tracing_status', sa.String(16)))
    op.create_table(
        'listener_otlp_collector_pool',
        sa.Column('listener_id', sa.String(36), nullable=False),
        sa.Column('pool_id', sa.String(36), nullable=False),
        sa.PrimaryKeyConstraint('listener_id'),
        sa.ForeignKeyConstraint(
            ['listener_id'], ['listener.id'], ondelete='CASCADE',
            name='fk_listener_otlp_collector_listener_id'),
        sa.ForeignKeyConstraint(
            ['pool_id'], ['pool.id'],
            name='fk_listener_otlp_collector_pool_id'))
    op.create_index('ix_listener_otlp_collector_pool_pool_id',
                    'listener_otlp_collector_pool', ['pool_id'])
