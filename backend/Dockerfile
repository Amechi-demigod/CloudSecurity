FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Run as an unprivileged user; SQLite DB lives on a volume at /data.
RUN useradd --create-home --uid 10001 cnapp && mkdir -p /data && chown cnapp /data
USER cnapp
ENV DATABASE_URL=sqlite:////data/cnapp.db

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
