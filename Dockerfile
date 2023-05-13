FROM python:3.9-alpine

RUN apk add --no-cache --virtual .build-deps \
                                  curl

# Configura la carpeta de trabajo

# Copia los archivos de la aplicación
COPY /www .

RUN curl https://bootstrap.pypa.io/get-pip.py -o /get-pip.py  \
    && python /get-pip.py

# Instala las dependencias
RUN pip install -r requirements.txt && python manage.py migrate


# Define el puerto en el que se ejecutará la aplicación
EXPOSE 8000

# Ejecuta el servidor cuando el contenedor se inicie
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]