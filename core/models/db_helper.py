from asyncio import current_task


from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from core.config import Settings

class DatabaseHelper:
    def __init__(self, url: str, echo: bool = False):
        self.engine = create_async_engine(
            url=url,
            echo=echo,
        )
        self.session_factory = async_sessionmaker()