import datetime as dt
from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    String,
)
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()


class Route(Base):
    __tablename__ = 'routes'
    id = Column(Integer, primary_key=True)
    auth_type = Column(String, nullable=False)
    route_view_method = Column(String, nullable=False)
    route = Column(String, nullable=False)
    route_name = Column(String, nullable=False, unique=True)
    created_at = Column(DateTime(timezone=False), nullable=False, default=dt.datetime.utcnow())
