FROM python:3.13-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY entrypoint.sh /entrypoint.sh
RUN useradd -r -u 10001 app && mkdir /data && chmod +x /entrypoint.sh
ENV DB_PATH=/data/accounts.db TRUST_PROXY=1
EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
