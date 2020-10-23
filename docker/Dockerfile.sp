FROM python:3.8

RUN apt-get update -y && apt-get -y install libxml2-dev libxmlsec1-dev libxmlsec1-openssl

WORKDIR /app

COPY requirements.txt .

RUN python -m pip install -r requirements.txt

COPY . .

CMD ["python", "-m", "flask", "run", "--host", "0.0.0.0"]