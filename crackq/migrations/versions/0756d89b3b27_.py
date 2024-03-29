"""empty message

Revision ID: 0756d89b3b27
Revises: 
Create Date: 2020-06-13 07:30:01.297335

"""
from alembic import op
import sqlalchemy as sa

import sqlalchemy_utils

# revision identifiers, used by Alembic.
revision = '0756d89b3b27'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    try:
        op.drop_table('sessions')
    except Exception:
        pass
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('sessions',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('session_id', sa.VARCHAR(length=255), nullable=True),
    sa.Column('data', sa.BLOB(), nullable=True),
    sa.Column('expiry', sa.DATETIME(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('session_id')
    )
    # ### end Alembic commands ###
