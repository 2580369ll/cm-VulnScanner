"""数据库初始化与基类"""

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

_connect_args = {}
if 'sqlite' in settings.database_url:
    _connect_args['check_same_thread'] = False

engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
    connect_args=_connect_args,
)

async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    # 必须在 create_all 前导入所有模型，确保 SQLAlchemy 能解析 relationship
    import app.models.task  # noqa
    import app.models.vulnerability  # noqa

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
