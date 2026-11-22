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

"""Add virtual HTTPS host sections and L7 policy ownership."""

from alembic import op
import sqlalchemy as sa


revision = '8d91efc431cf'
down_revision = '4af74f137cb9'


def upgrade():
    op.add_column('listener', sa.Column('https_virtual_hosts',
                                        sa.JSON(none_as_null=True)))
    op.add_column('l7policy', sa.Column('https_listener_hostname',
                                        sa.String(253), nullable=True))
