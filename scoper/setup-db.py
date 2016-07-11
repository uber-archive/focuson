#!/usr/bin/env python
"""Creates tables in DB."""

from sqlalchemy import create_engine
from scoper_lib.db.models import Base

engine = create_engine('sqlite:///scoper.db', echo=True)
Base.metadata.create_all(engine)
