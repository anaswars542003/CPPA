FROM gcc:latest

WORKDIR /app

COPY . /app

CMD ["gcc", "driver.c", "-I./include", "sok.a", "libmiracl.a", "-o", "driver"]
