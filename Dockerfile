FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shortener shortener
RUN useradd -m app && mkdir /data && chown app /data
USER app
ENV SHORTENER_DB=/data/short.db SHORTENER_HOST=sho.rt RESOLVE_DNS=1
EXPOSE 8080
CMD ["uvicorn", "shortener.app:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header", "--proxy-headers"]
