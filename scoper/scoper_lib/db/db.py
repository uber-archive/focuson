from contextlib import contextmanager
from functools import wraps
from sqlalchemy import create_engine
from sqlalchemy.orm import (
    scoped_session,
    sessionmaker,
)

engine = create_engine('sqlite:///scoper.db')
session_factory = sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def db_session():
    session = scoped_session(session_factory)
    try:
        yield session
        session.commit()
    except:
        session.rollback()
        raise
    finally:
        session.close()


def with_session(func):
    @wraps(func)
    def wrapped_func(*args, **kwargs):
        with db_session() as session:
            return func(session, *args, **kwargs)
    return wrapped_func
