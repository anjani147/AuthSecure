
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    username = Column(
        String(50),
        unique=True,
        nullable=False
    )

    password_hash = Column(
        String,
        nullable=False
    )

    role = Column(
        String(20),
        nullable=False,
        default="user",
        server_default="user"
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    token_hash = Column(
        String(64),
        unique=True,
        nullable=False
    )

    expires_at = Column(
        DateTime,
        nullable=False
    )
