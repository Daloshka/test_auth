from sqlalchemy.orm import as_declarative, Mapped, mapped_column, declared_attr

@as_declarative()
class Base():
    __abstract__ = True

    @declared_attr.derictive
    def __tablename__(cls) -> str:
        return f"{cls.__name__.lower()}s"

    id: Mapped[int] = mapped_column(primary_key=True)