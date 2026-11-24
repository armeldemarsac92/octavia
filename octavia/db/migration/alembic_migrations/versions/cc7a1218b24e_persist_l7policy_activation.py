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

"""Persist the request and recovery phase on the owning load balancer."""

from alembic import op
import sqlalchemy as sa

from octavia.i18n import _


revision = 'cc7a1218b24e'
down_revision = '8162e054c7ba'


def upgrade():
    listener = sa.table('listener', sa.column('l7policy_activation_id'))
    pending = sa.select(listener.c.l7policy_activation_id).where(
        listener.c.l7policy_activation_id.is_not(None)).limit(1)
    if (not op.get_context().as_sql and
            op.get_bind().execute(pending).first()):
        raise RuntimeError(_('Drain pending L7 policy activations before '
                             'upgrading.'))
    op.add_column('load_balancer', sa.Column('l7policy_graph_generation',
                                             sa.String(36), nullable=True))
    op.add_column('load_balancer', sa.Column('l7policy_activation',
                                             sa.JSON(none_as_null=True)))
    op.drop_column('listener', 'l7policy_activation_id')
