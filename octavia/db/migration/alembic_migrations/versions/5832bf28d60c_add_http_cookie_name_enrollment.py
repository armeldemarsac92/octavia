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
"""Distinguish enrolled HTTP_COOKIE names from legacy inert values.

Revision ID: 5832bf28d60c
Revises: 20feeba4b451
"""

from alembic import op
import sqlalchemy as sa

revision = '5832bf28d60c'
down_revision = '20feeba4b451'


def upgrade():
    op.add_column('session_persistence', sa.Column(
        'http_cookie_name_enabled', sa.Boolean(), nullable=False,
        server_default=sa.false()))
