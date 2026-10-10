# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Retain revision-pinned Git source URLs on packages."""

from alembic import op
import sqlalchemy as sa


revision = 'a9c6e28f3410'
down_revision = 'cc5359c88dd2'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('packages', schema=None) as batch_op:
        batch_op.add_column(sa.Column('source_urls', sa.JSON(), nullable=True))


def downgrade():
    with op.batch_alter_table('packages', schema=None) as batch_op:
        batch_op.drop_column('source_urls')
