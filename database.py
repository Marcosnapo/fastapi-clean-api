# database.py
# Este archivo configura la conexión a la base de datos PostgreSQL
# y proporciona una función para obtener sesiones de base de datos.

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base # Necesario para definir 'Base'
import os

# Importa 'Base' desde models.py. 'Base' es el cimiento para tus modelos SQLAlchemy.
from models import Base

# Obtiene la URL de conexión a la base de datos de las variables de entorno.
# Es crucial que esta variable esté configurada tanto en tu entorno local como en Render.
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    # Si la variable no está configurada, lanza una excepción para evitar que la aplicación inicie sin DB.
    raise Exception("DATABASE_URL environment variable is not set.")

# Crea el motor de la base de datos. 'pool_pre_ping' ayuda a mantener las conexiones activas.
engine = create_engine(DATABASE_URL, pool_pre_ping=True)

# Configura la clase SessionLocal, que será una "fábrica" para nuevas sesiones de base de datos.
# 'autocommit=False' asegura que las transacciones deben ser confirmadas explícitamente.
# 'autoflush=False' evita que los objetos se sincronicen automáticamente con la DB antes de un commit.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Función de utilidad para obtener una sesión de base de datos.
# Utiliza 'yield' para que la sesión se cierre automáticamente después de su uso (dependencia de FastAPI).
def get_db():
    db = SessionLocal() # Crea una nueva sesión de base de datos
    try:
        yield db # Proporciona la sesión a la ruta de la API
    finally:
        db.close() # Asegura que la sesión se cierre al finalizar

# Función para crear todas las tablas definidas en tus modelos SQLAlchemy.
# Se llama al inicio de la aplicación para asegurar que la estructura de la DB esté lista.
def create_db_tables():
    print("Attempting to create database tables...")
    # Base.metadata.create_all() crea todas las tablas para las que 'Base' tiene metadatos.
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully or already exist.")
