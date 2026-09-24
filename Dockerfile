FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py oauth_auth.py smoke_test.py oauth_check.py ./
RUN chmod 0755 /app && chmod 0644 /app/*.py /app/requirements.txt
USER 10001:10001
EXPOSE 8000
CMD ["python", "server.py"]
