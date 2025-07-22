# models.py
# Este archivo define los modelos de SQLAlchemy para la base de datos
# y los esquemas Pydantic para la validación de datos de la API.

from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
# Importa funciones para hashear y verificar contraseñas.
# Aunque security.py las encapsula, models.py las necesita para el método set_password del User.
from werkzeug.security import generate_password_hash, check_password_hash

# Importaciones para Pydantic: BaseModel para definir esquemas, ConfigDict para configuración.
from pydantic import BaseModel, ConfigDict

# Define la base declarativa para tus modelos SQLAlchemy.
# Todos los modelos de base de datos heredarán de esta 'Base'.
Base = declarative_base()

# --- SQLAlchemy Models (Modelos para la base de datos) ---

class User(Base):
    """
    Modelo SQLAlchemy para la tabla 'users' en la base de datos.
    Representa a un usuario de la aplicación.
    """
    __tablename__ = "users" # Nombre de la tabla en la base de datos

    id = Column(Integer, primary_key=True, index=True) # Clave primaria, autoincremental
    username = Column(String(80), unique=True, nullable=False) # Nombre de usuario, debe ser único y no nulo
    password_hash = Column(String(255), nullable=False) # Hash de la contraseña, tamaño suficiente para bcrypt

    # Relación uno-a-muchos con el modelo Todo.
    # 'back_populates' crea una relación bidireccional.
    todos = relationship("Todo", back_populates="owner")

    def __repr__(self):
        """Representación de cadena para depuración."""
        return f'<User {self.username}>'

    def set_password(self, password):
        """Hashea la contraseña y la asigna a password_hash."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verifica si la contraseña plana coincide con el hash almacenado."""
        return check_password_hash(self.password_hash, password)

class Todo(Base):
    """
    Modelo SQLAlchemy para la tabla 'todos' en la base de datos.
    Representa una tarea individual.
    """
    __tablename__ = "todos" # Nombre de la tabla en la base de datos

    id = Column(Integer, primary_key=True, index=True) # Clave primaria, autoincremental
    title = Column(String(255), nullable=False) # Título de la tarea, no nulo
    description = Column(String(255), nullable=True) # Descripción de la tarea, puede ser nula
    completed = Column(Boolean, default=False) # Estado de la tarea, por defecto falso
    owner_id = Column(Integer, ForeignKey("users.id")) # Clave foránea que referencia el ID del usuario propietario

    # Relación muchos-a-uno con el modelo User.
    # 'back_populates' crea una relación bidireccional.
    owner = relationship("User", back_populates="todos")

    def __repr__(self):
        """Representación de cadena para depuración."""
        return f'<Todo {self.title}>'


# --- Pydantic Models (Esquemas para la validación de datos de la API) ---

class UserBase(BaseModel):
    """Esquema base para datos de usuario."""
    username: str

class UserCreate(UserBase):
    """Esquema para la creación de un nuevo usuario (incluye contraseña)."""
    password: str

class UserInDB(UserBase):
    """Esquema para la representación de un usuario tal como se almacena en la DB (sin hash de contraseña)."""
    id: int # El ID es asignado por la DB
    model_config = ConfigDict(from_attributes=True) # Permite la conversión de objetos ORM a Pydantic

class TodoBase(BaseModel):
    """Esquema base para datos de tarea."""
    title: str
    description: str | None = None # La descripción es opcional
    completed: bool = False # Por defecto, la tarea no está completada

class TodoCreate(TodoBase):
    """Esquema para la creación de una nueva tarea."""
    pass # No añade campos adicionales a TodoBase

class TodoInDB(TodoBase):
    """Esquema para la representación de una tarea tal como se almacena en la DB."""
    id: int # El ID es asignado por la DB
    owner_id: int # El ID del propietario es asignado por la API
    model_config = ConfigDict(from_attributes=True) # Permite la conversión de objetos ORM a Pydantic

# --- Pydantic Models para Autenticación ---

class Token(BaseModel):
    """Esquema para la respuesta de un token de acceso."""
    access_token: str # El token JWT
    token_type: str = "bearer" # Tipo de token, por defecto "bearer"

class TokenData(BaseModel):
    """Esquema para los datos contenidos dentro del token JWT."""
    username: str | None = None # El nombre de usuario del token

class UserLogin(BaseModel):
    """Esquema para las credenciales de inicio de sesión."""
    username: str
    password: str
