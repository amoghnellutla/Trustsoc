"""add_cases_tables

Revision ID: 27840a650004
Revises: d198113371aa
Create Date: 2026-04-01

Adds: cases, case_incidents (association), case_notes tables.
Skips: index/FK changes on existing tables (Supabase view blocks them).
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '27840a650004'
down_revision: Union[str, None] = 'd198113371aa'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'cases',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=True),
        sa.Column('severity', sa.String(length=50), nullable=True),
        sa.Column('assigned_to', sa.String(length=255), nullable=True),
        sa.Column('created_by', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_cases_created_at'), 'cases', ['created_at'], unique=False)
    op.create_index(op.f('ix_cases_severity'), 'cases', ['severity'], unique=False)
    op.create_index(op.f('ix_cases_status'), 'cases', ['status'], unique=False)

    op.create_table(
        'case_incidents',
        sa.Column('case_id', sa.UUID(), nullable=False),
        sa.Column('incident_id', sa.UUID(), nullable=False),
        sa.Column('added_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id']),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id']),
        sa.PrimaryKeyConstraint('case_id', 'incident_id'),
    )

    op.create_table(
        'case_notes',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('case_id', sa.UUID(), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('author', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_case_notes_case_id'), 'case_notes', ['case_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_case_notes_case_id'), table_name='case_notes')
    op.drop_table('case_notes')
    op.drop_table('case_incidents')
    op.drop_index(op.f('ix_cases_status'), table_name='cases')
    op.drop_index(op.f('ix_cases_severity'), table_name='cases')
    op.drop_index(op.f('ix_cases_created_at'), table_name='cases')
    op.drop_table('cases')
