FROM python:3.9
ENV PYTHONUNBUFFERED 1
WORKDIR /mondeo
COPY . /mondeo
RUN mkdir -p outputs
COPY requirements.txt /app/requirements.txt
RUN /usr/local/bin/python -m pip install --upgrade pip
RUN pip install -r requirements.txt
RUN pip install numpy --upgrade
EXPOSE 5002
CMD ["python", "main.py"]
