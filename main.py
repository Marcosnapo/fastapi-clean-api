# main.py
# Este es el archivo principal de tu aplicación FastAPI.
# Define la aplicación, las rutas (endpoints) y maneja las dependencias.

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm # Para el formulario de login OAuth2
from sqlalchemy import text # Para ejecutar consultas SQL simples (ej. test de conexión)
from sqlalchemy.orm import Session # Para manejar sesiones de base de datos
from sqlalchemy.exc import SQLAlchemyError # Para manejar errores de SQLAlchemy
import os # Para acceder a variables de entorno
from typing import Annotated # Para usar Annotated en las dependencias de FastAPI
from datetime import timedelta # Para calcular la expiración del token

# Importa tus modelos SQLAlchemy y Pydantic desde models.py
from models import User, UserCreate, UserInDB, Todo, TodoCreate, TodoInDB, UserLogin, Token

# Importa las funciones de seguridad desde security.py
from security import (
    authenticate_user,
    create_access_token,
    get_current_user,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    get_password_hash
)

# Importa la configuración de la base de datos y la función para crear tablas desde database.py
from database import get_db, create_db_tables

# Importa el middleware CORS para manejar solicitudes de diferentes orígenes (frontend).
from fastapi.middleware.cors import CORSMiddleware

# Inicializa la aplicación FastAPI.
app = FastAPI()

# --- Configuración de CORS (Cross-Origin Resource Sharing) ---
# Permite que tu frontend (ej. React en localhost:3000) pueda comunicarse con tu backend.
origins = [
    "http://localhost",
    "http://localhost:3000", # Puerto común para aplicaciones React/Vite
    "http://localhost:5173",
    "https://todo-app-frontend-m75j.onrender.com",
    # ¡IMPORTANTE! Cuando despliegues tu frontend, añade aquí su URL de producción (ej. "https://tu-frontend.onrender.com")
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins, # Lista de orígenes permitidos
    allow_credentials=True, # Permite cookies, encabezados de autorización, etc.
    allow_methods=["*"], # Permite todos los métodos HTTP (GET, POST, PUT, DELETE, etc.)
    allow_headers=["*"], # Permite todos los encabezados
)

# --- Eventos de la Aplicación ---

@app.on_event("startup")
async def startup_event():
    """
    Función que se ejecuta cuando la aplicación FastAPI se inicia.
    Aquí se crean las tablas de la base de datos si no existen.
    """
    create_db_tables() # Llama a la función para crear tablas desde database.py

# --- Rutas (Endpoints) de la API ---

@app.get("/")
async def read_root():
    """Ruta de bienvenida para verificar que la API está funcionando."""
    return {"message": "Welcome to Minimal Todo Backend with FastAPI!"}

@app.get("/test-db-connection")
async def test_db_connection(db: Session = Depends(get_db)):
    """
    Ruta para probar la conexión a la base de datos.
    Intenta ejecutar una consulta simple para verificar la conectividad.
    """
    try:
        # Ejecuta una consulta SQL simple para verificar la conexión
        result = db.execute(text("SELECT 1")).scalar_one()
        return {"status": "success", "message": "Database connection successful!", "result": result}
    except Exception as e:
        # Si hay un error, devuelve un error HTTP 500
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Database connection failed: {e}")

# --- Rutas de Usuarios ---
@app.options("/register", status_code=status.HTTP_200_OK)
async def options_register():
    """
    Maneja las peticiones OPTIONS para la ruta /register.
    Esto es necesario para CORS preflight requests.
    """
    return {} # Devuelve una respuesta vacía con status 200 OK

@app.post("/register", response_model=UserInDB, status_code=status.HTTP_201_CREATED)
def register_user_fastapi(user: UserCreate, db: Session = Depends(get_db)):
    """
    Registra un nuevo usuario en la base de datos.
    Hashea la contraseña antes de almacenarla.
    """
    # Verifica si el nombre de usuario ya existe
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, # Código 409: Conflicto
            detail="El nombre de usuario ya existe"
        )

    # Hashea la contraseña usando la función de seguridad
    hashed_password = get_password_hash(user.password)
    # Crea un nuevo objeto User para la base de datos
    new_user = User(username=user.username, password_hash=hashed_password)

    try:
        db.add(new_user) # Añade el nuevo usuario a la sesión
        db.commit() # Confirma la transacción en la base de datos
        db.refresh(new_user) # Actualiza el objeto usuario con el ID generado por la DB
        return new_user # Devuelve el usuario registrado
    except SQLAlchemyError as e:
        db.rollback() # Si hay un error, revierte la transacción
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno del servidor al registrar usuario: {e}"
        )

@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], # Dependencia para manejar datos de formulario de login
    db: Session = Depends(get_db) # Dependencia para la sesión de base de datos
):
    """
    Permite a un usuario iniciar sesión y obtener un token de acceso JWT.
    """
    # Autentica al usuario usando la función de seguridad
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, # Código 401: No autorizado
            detail="Nombre de usuario o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"}, # Encabezado para indicar el tipo de autenticación
        )
    # Calcula el tiempo de expiración del token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # Crea el token de acceso JWT
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    # Devuelve el token de acceso y el tipo de token
    return {"access_token": access_token, "token_type": "bearer"}

# --- Rutas de Tareas (Protegidas por Autenticación) ---

@app.post("/todos/", response_model=TodoInDB, status_code=status.HTTP_201_CREATED)
def create_todo(
    todo: TodoCreate, # Datos de la tarea a crear (validados por Pydantic)
    current_user: Annotated[User, Depends(get_current_user)], # Dependencia: Requiere un usuario autenticado
    db: Session = Depends(get_db) # Dependencia para la sesión de base de datos
):
    """
    Crea una nueva tarea asociada al usuario actualmente autenticado.
    """
    # Crea un nuevo objeto Todo para la base de datos, asignando el owner_id del usuario autenticado
    db_todo = Todo(
        title=todo.title,
        description=todo.description,
        completed=todo.completed,
        owner_id=current_user.id # Asigna la tarea al usuario autenticado
    )
    try:
        db.add(db_todo) # Añade la nueva tarea a la sesión
        db.commit() # Confirma la transacción
        db.refresh(db_todo) # Actualiza el objeto tarea con el ID generado
        return db_todo # Devuelve la tarea creada
    except SQLAlchemyError as e:
        db.rollback() # Revierte la transacción en caso de error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al crear tarea: {e}"
        )

@app.get("/todos/", response_model=list[TodoInDB])
def read_todos(
    current_user: Annotated[User, Depends(get_current_user)], # Requiere autenticación
    skip: int = 0, # Parámetro de paginación: cuántos elementos saltar
    limit: int = 100, # Parámetro de paginación: cuántos elementos devolver
    db: Session = Depends(get_db) # Dependencia de DB
):
    """
    Obtiene todas las tareas pertenecientes al usuario actualmente autenticado.
    Soporta paginación con 'skip' y 'limit'.
    """
    # Filtra las tareas por el owner_id del usuario autenticado
    todos = db.query(Todo).filter(Todo.owner_id == current_user.id).offset(skip).limit(limit).all()
    return todos

@app.get("/todos/{todo_id}", response_model=TodoInDB)
def read_todo(
    todo_id: int, # ID de la tarea a obtener
    current_user: Annotated[User, Depends(get_current_user)], # Requiere autenticación
    db: Session = Depends(get_db) # Dependencia de DB
):
    """
    Obtiene una tarea específica por su ID, solo si pertenece al usuario autenticado.
    """
    # Busca la tarea por ID y verifica que el owner_id coincida con el usuario autenticado
    todo = db.query(Todo).filter(Todo.id == todo_id, Todo.owner_id == current_user.id).first()
    if todo is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tarea no encontrada o no tienes permiso para verla")
    return todo

@app.put("/todos/{todo_id}", response_model=TodoInDB)
def update_todo(
    todo_id: int, # ID de la tarea a actualizar
    todo_update: TodoCreate, # Datos actualizados de la tarea
    current_user: Annotated[User, Depends(get_current_user)], # Requiere autenticación
    db: Session = Depends(get_db) # Dependencia de DB
):
    """
    Actualiza una tarea existente por su ID, solo si pertenece al usuario autenticado.
    """
    # Busca la tarea y verifica la propiedad
    todo = db.query(Todo).filter(Todo.id == todo_id, Todo.owner_id == current_user.id).first()
    if todo is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tarea no encontrada o no tienes permiso para actualizarla")

    # Actualiza los campos de la tarea con los datos proporcionados
    todo.title = todo_update.title
    todo.description = todo_update.description
    todo.completed = todo_update.completed

    try:
        db.commit() # Confirma los cambios
        db.refresh(todo) # Actualiza el objeto
        return todo # Devuelve la tarea actualizada
    except SQLAlchemyError as e:
        db.rollback() # Revierte en caso de error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al actualizar tarea: {e}"
        )

@app.delete("/todos/{todo_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_todo(
    todo_id: int, # ID de la tarea a eliminar
    current_user: Annotated[User, Depends(get_current_user)], # Requiere autenticación
    db: Session = Depends(get_db) # Dependencia de DB
):
    """
    Elimina una tarea existente por su ID, solo si pertenece al usuario autenticado.
    """
    # Busca la tarea y verifica la propiedad
    todo = db.query(Todo).filter(Todo.id == todo_id, Todo.owner_id == current_user.id).first()
    if todo is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tarea no encontrada o no tienes permiso para eliminarla")

    try:
        db.delete(todo) # Elimina la tarea de la sesión
        db.commit() # Confirma la eliminación
        return # Devuelve una respuesta vacía (204 No Content)
    except SQLAlchemyError as e:
        db.rollback() # Revierte en caso de error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al eliminar tarea: {e}"
        )
