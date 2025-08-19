"""merge oauth and main migration heads

Revision ID: 813b45a70b53
Revises: 34492f99a0c4, add_oauth_tokens_table
Create Date: 2025-08-19 01:25:29.721681

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '813b45a70b53'
down_revision: Union[str, Sequence[str], None] = ('34492f99a0c4', 'add_oauth_tokens_table')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
