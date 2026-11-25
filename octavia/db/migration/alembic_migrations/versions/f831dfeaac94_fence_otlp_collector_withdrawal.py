# SPDX-License-Identifier: Apache-2.0

"""Fence collector withdrawal until Amphora acknowledges publication.

Revision ID: f831dfeaac94
Revises: 6529f4796d83
"""

from alembic import op
import sqlalchemy as sa

revision = 'f831dfeaac94'
down_revision = '6529f4796d83'


def upgrade():
    op.add_column('listener', sa.Column(
        'otlp_tracing_revision', sa.String(36)))
    table = 'listener_otlp_collector_pool'
    dialect = op.get_context().dialect.name
    if dialect in ('mysql', 'mariadb'):
        # Keep the leading listener_id foreign-key index throughout the ALTER.
        op.execute(sa.text(
            'ALTER TABLE listener_otlp_collector_pool DROP PRIMARY KEY, '
            'ADD PRIMARY KEY (listener_id, pool_id)'))
    else:
        name = f'{table}_pkey' if dialect == 'postgresql' else f'pk_{table}'
        with op.batch_alter_table(
                table, naming_convention={'pk': 'pk_%(table_name)s'}) as batch:
            batch.drop_constraint(name, type_='primary')
            batch.create_primary_key(name, ['listener_id', 'pool_id'])
