FROM python:3

WORKDIR /app

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
        pkg-config libssl-dev build-essential xml-security-c-utils libxmlsec1-dev libclang-dev clang llvm libxml2-dev


COPY requirements.txt .

RUN python3 -m pip install -r requirements.txt

COPY . .

CMD ["./entrypoint.py"]