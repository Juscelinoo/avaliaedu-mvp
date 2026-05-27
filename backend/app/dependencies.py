from dotenv import load_dotenv
load_dotenv()
import os
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from app.database import get_db
from app import models

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def get_usuario_atual(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> models.Usuario:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token inválido ou expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    usuario = db.query(models.Usuario).filter(models.Usuario.email == email).first()
    if usuario is None:
        raise credentials_exception
    return usuario

def get_usuario_admin(usuario: models.Usuario = Depends(get_usuario_atual)) -> models.Usuario:
    if usuario.perfil != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Apenas administradores podem acessar este recurso",
        )
    return usuario

def get_usuario_atual(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    print(f"🔍 Token recebido: {token[:20]}...")  # só para ver se chegou
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        print(f"📧 Email extraído: {email}")
        if email is None:
            raise HTTPException(status_code=401, detail="Token sem email")
    except JWTError as e:
        print(f"❌ Erro JWT: {e}")
        raise HTTPException(status_code=401, detail="Token inválido")

    usuario = db.query(models.Usuario).filter(models.Usuario.email == email).first()
    print(f"👤 Usuário encontrado? {usuario is not None}")
    if not usuario:
        raise HTTPException(status_code=401, detail="Usuário não encontrado")
    return usuario