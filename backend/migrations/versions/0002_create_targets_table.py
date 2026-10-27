"""create targets table

Revision ID: 0002
Revises: 135fafe2c0e3
Create Date: 2026-10-27 23:53:50.243504

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | Sequence[str] | None = "135fafe2c0e3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "targets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("verification_token", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_targets_user_id_users"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_targets")),
        sa.UniqueConstraint("user_id", "domain", name=op.f("uq_targets_user_id_domain")),
    )
    op.create_index(op.f("ix_targets_user_id"), "targets", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_targets_user_id"), table_name="targets")
    op.drop_table("targets")
