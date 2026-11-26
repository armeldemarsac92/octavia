# Copyright 2026
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from alembic import op
import sqlalchemy as sa

revision = '047259f107e6'
down_revision = 'e82a623f3439'


def upgrade():
    op.add_column('listener', sa.Column('tcp_default_pool_tls', sa.Boolean(),
                                        nullable=False,
                                        server_default=sa.false()))
