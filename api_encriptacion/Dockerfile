# Usa la imagen oficial de Python
FROM python:3.13

# Establece el directorio de trabajo
WORKDIR /app

# Copia los archivos
COPY requirements.txt .
COPY main.py .

# Instala dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Expone el puerto de la app
EXPOSE 8000

# Comando para ejecutar la API
CMD ["uvicorn", "main:app","--reload", "--host", "0.0.0.0", "--port", "8000"]
