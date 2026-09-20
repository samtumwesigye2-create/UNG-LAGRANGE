FROM python:3.12-slim
WORKDIR /srv
COPY pyproject.toml ./
COPY app ./app
COPY ung_lagrange_adapter ./ung_lagrange_adapter
RUN pip install --no-cache-dir .
ENV PORT=8000
EXPOSE 8000
CMD ["python", "-m", "app.run"]
