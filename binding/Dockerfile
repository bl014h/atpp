# Redthread agent passport verifier binding (Apache-2.0). Built from the output of tools/atpp/binding/build.py;
# REVISION names the source version and commit it was built from.
FROM python:3.12-slim
RUN pip install --no-cache-dir cryptography==49.0.0
WORKDIR /verifier
COPY . /verifier
USER nobody
EXPOSE 8080
CMD ["python3", "verifier_http.py", "8080"]
