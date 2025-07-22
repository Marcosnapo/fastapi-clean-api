# security.py
# Este archivo maneja toda la lógica de seguridad:
# - Hashing y verificación de contraseñas.
# - Creación y verificación de JSON Web Tokens (JWT).
# - Dependencias de FastAPI para la autenticación de usuarios.

from datetime import datetime, timedelta, timezone
from typing import Annotated # Para usar Annotated en las dependencias de FastAPI

from fastapi import Depends, HTTPException, status # Para manejar dependencias y excepciones HTTP
from fastapi.security import OAuth2PasswordBearer # Esquema de seguridad OAuth2
from jose import JWTError, jwt # Librería para JWT
from passlib.context import CryptContext # Librería para hashing de contraseñas

# Importa los modelos de usuario y los datos del token desde models.py
from models import User, TokenData
from sqlalchemy.orm import Session # Para interactuar con la base de datos

# Importa la función para obtener la sesión de la base de datos desde database.py
from database import get_db

# --- Configuración de Seguridad ---
# ¡IMPORTANTE! Esta clave secreta debe ser un valor FUERTE y aleatorio,
# y debe almacenarse de forma SEGURA (ej. en variables de entorno) en producción.
# ¡Nunca la hardcodees como está aquí en un entorno real!
SECRET_KEY = "tu_super_secreta_clave_jwt_cambiala_en_produccion_y_usa_env_vars"
ALGORITHM = "HS256" # Algoritmo de cifrado para JWT (ej. HS256, RS256)
ACCESS_TOKEN_EXPIRE_MINUTES = 30 # Tiempo de expiración del token de acceso en minutos

# Contexto para el hashing de contraseñas.
# 'bcrypt' es un algoritmo de hashing seguro y recomendado.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Esquema de seguridad OAuth2.
# 'tokenUrl="token"' indica la ruta de la API donde el cliente puede obtener un token.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Funciones de Hashing de Contraseñas ---

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica si una contraseña plana coincide con un hash de contraseña."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hashea una contraseña plana."""
    return pwd_context.hash(password)

# --- Funciones de JWT (JSON Web Token) ---

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """
    Crea un token de acceso JWT.
    :param data: Diccionario de datos a incluir en el token (ej. {"sub": username}).
    :param expires_delta: Duración opcional del token. Si no se especifica, usa 15 minutos.
    :return: El token JWT codificado.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire}) # Añade el tiempo de expiración al payload
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM) # Codifica el token
    return encoded_jwt

def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)) -> User:
    """
    Dependencia de FastAPI para obtener el usuario actual autenticado.
    Verifica el token JWT y busca el usuario en la base de datos.
    :param token: El token de acceso proporcionado en el encabezado de autorización.
    :param db: Sesión de la base de datos.
    :return: El objeto User del usuario autenticado.
    :raises HTTPException: Si las credenciales no son válidas o el token es incorrecto/expirado.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decodifica el token usando la clave secreta y el algoritmo.
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub") # 'sub' (subject) es el nombre de usuario
        if username is None:
            raise credentials_exception # Si no hay nombre de usuario en el token, credenciales inválidas
        token_data = TokenData(username=username) # Crea un objeto TokenData
    except JWTError:
        raise credentials_exception # Si hay un error al decodificar el token, credenciales inválidas

    # Busca el usuario en la base de datos usando el nombre de usuario del token.
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception # Si el usuario no existe en la DB, credenciales inválidas
    return user # Devuelve el objeto User autenticado

def authenticate_user(username: str, password: str, db: Session) -> User | bool:
    """
    Autentica un usuario verificando su nombre de usuario y contraseña.
    :param username: Nombre de usuario proporcionado.
    :param password: Contraseña plana proporcionada.
    :param db: Sesión de la base de datos.
    :return: El objeto User si la autenticación es exitosa, False en caso contrario.
    """
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False # Usuario no encontrado
    # Verifica la contraseña hasheada almacenada con la contraseña plana proporcionada.
    if not verify_password(password, user.password_hash):
        return False # Contraseña incorrecta
    return user # Autenticación exitosa, devuelve el objeto User
