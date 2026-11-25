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

"""Store ordered listener request filters with foreign keys to auth pools."""

from alembic import op
import sqlalchemy as sa


revision = 'cadb700cba48'
down_revision = 'b22da9155c2b'


def upgrade():
    op.add_column('listener', sa.Column(
        'request_filter_sections', sa.JSON(none_as_null=True)))
    op.create_table(
        'listener_request_filter_pool',
        sa.Column('listener_id', sa.String(36), primary_key=True),
        sa.Column('pool_id', sa.String(36), primary_key=True),
        sa.ForeignKeyConstraint(
            ['listener_id'], ['listener.id'], ondelete='CASCADE',
            name='fk_listener_request_filter_listener_id'),
        sa.ForeignKeyConstraint(
            ['pool_id'], ['pool.id'],
            name='fk_listener_request_filter_pool_id'))
    op.create_index('ix_listener_request_filter_pool_pool_id',
                    'listener_request_filter_pool', ['pool_id'])
