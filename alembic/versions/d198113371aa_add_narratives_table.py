"""add_narratives_table

Revision ID: d198113371aa
Revises: 58a01322819a
Create Date: 2026-04-01 03:12:30.410705

Trimmed to only safe additions:
  - narratives table (new)
  - enrichments.cost_usd, cached, api_calls_made columns (new)
Skipped: timestamp timezone alterations (Supabase view blocks them)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'd198113371aa'
down_revision: Union[str, None] = '58a01322819a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── New: narratives table ───────────────────────────────────────────────
    op.create_table(
        'narratives',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('alert_id', sa.UUID(), nullable=True),
        sa.Column('incident_id', sa.UUID(), nullable=True),
        sa.Column('narrative_text', sa.Text(), nullable=False),
        sa.Column('what_happened', sa.Text(), nullable=True),
        sa.Column('what_we_know', sa.Text(), nullable=True),
        sa.Column('recommended_actions', sa.Text(), nullable=True),
        sa.Column('model_used', sa.String(length=100), nullable=True),
        sa.Column('token_count', sa.Integer(), nullable=True),
        sa.Column('cost_usd', sa.DECIMAL(precision=10, scale=6), nullable=True),
        sa.Column('is_mock', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id']),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_narratives_alert_id'), 'narratives', ['alert_id'], unique=False)
    op.create_index(op.f('ix_narratives_created_at'), 'narratives', ['created_at'], unique=False)
    op.create_index(op.f('ix_narratives_incident_id'), 'narratives', ['incident_id'], unique=False)

    # ── New: enrichment cost tracking columns ───────────────────────────────
    # Use try/except blocks so re-running is safe (columns may already exist
    # if create_all ran before this migration was applied).
    try:
        op.add_column('enrichments', sa.Column('cost_usd', sa.DECIMAL(precision=10, scale=6), nullable=True))
    except Exception:
        pass
    try:
        op.add_column('enrichments', sa.Column('cached', sa.Boolean(), nullable=True))
    except Exception:
        pass
    try:
        op.add_column('enrichments', sa.Column('api_calls_made', sa.Integer(), nullable=True))
    except Exception:
        pass


def downgrade() -> None:
    op.drop_index(op.f('ix_narratives_incident_id'), table_name='narratives')
    op.drop_index(op.f('ix_narratives_created_at'), table_name='narratives')
    op.drop_index(op.f('ix_narratives_alert_id'), table_name='narratives')
    op.drop_table('narratives')
    op.drop_column('enrichments', 'api_calls_made')
    op.drop_column('enrichments', 'cached')
    op.drop_column('enrichments', 'cost_usd')
