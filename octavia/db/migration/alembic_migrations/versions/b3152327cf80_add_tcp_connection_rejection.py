# Copyright 2026 OpenStack contributors
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
"""Store TCP connection rejection and its pending batch identity."""

from alembic import op
import sqlalchemy as sa


revision = 'b3152327cf80'
down_revision = '5832bf28d60c'


def upgrade():
    op.add_column('pool', sa.Column(
        'tcp_connection_rejection', sa.JSON(none_as_null=True)))
    op.add_column('pool', sa.Column('tcp_member_batch_id', sa.String(36)))
    op.add_column('load_balancer', sa.Column(
        'tcp_member_batch', sa.JSON(none_as_null=True)))
    op.add_column('member', sa.Column(
        'tcp_batch_quota_released', sa.Boolean(), nullable=False,
        server_default=sa.false()))
